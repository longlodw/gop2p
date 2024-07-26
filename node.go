package gop2p

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"runtime"
	"sync"
	"time"
)

type Node struct {
  randomSecret []byte
  localPublicKeyED []byte
  localPrivateKeyED []byte
  udpConn *net.UDPConn
  ipToConnection map[string]*EncryptedConnection
  ipToHandshake map[string]*Handshake
  mutex sync.RWMutex
  incomingConnection chan incomingConnectionInfo
  runErrors chan error
  stopChan chan struct{}
}

type incomingConnectionInfo struct {
  addr *net.UDPAddr
  publicKeyED []byte
  aesSecret []byte
  publicKeyDH []byte
}

func NewNode(localPrivateKeyED []byte, localPublicKeyED []byte, udpAddr *net.UDPAddr) (*Node, error) {
  randomSecret := make([]byte, 32)
  n, err := rand.Read(randomSecret)
  if err != nil {
    return nil, err
  }
  if n != 32 {
    return nil, errors.New("Failed to generate random secret")
  }
  udpConn, err := net.ListenUDP("udp6", udpAddr)
  if err != nil {
    return nil, err
  }
  node := &Node{
    randomSecret: randomSecret,
    localPublicKeyED: localPublicKeyED,
    localPrivateKeyED: localPrivateKeyED,
    udpConn: udpConn,
    ipToConnection: make(map[string]*EncryptedConnection),
    ipToHandshake: make(map[string]*Handshake),
    incomingConnection: make(chan incomingConnectionInfo, 8),
    runErrors: make(chan error),
    stopChan: make(chan struct{}),
  }
  go func() {
    for {
      select {
      case <-node.stopChan:
	return
      default:
	node.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	err := node.run()
	if timeoutErr, ok := err.(net.Error); err == nil || (ok && timeoutErr.Timeout()) {
	    continue
	}
	node.runErrors <- err
      }
    }
  }()
  return node, nil
}

func (node *Node) CloseStream(addr *net.UDPAddr, streamID byte) error {
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    return errors.New("Connection not established")
  }
  closed, err := conn.closeStream(node.udpConn, streamID)
  if closed {
    close(conn.consumableBuffer)
    node.mutex.Lock()
    delete(node.ipToConnection, addr.String())
    node.mutex.Unlock()
  }
  if err != nil {
    return err
  }
  return nil
}

func (node *Node) ClosePeer(addr *net.UDPAddr) error {
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    return errors.New("Connection not established")
  }
  err := conn.close(node.udpConn)
  close(conn.consumableBuffer)
  node.mutex.Lock()
  delete(node.ipToConnection, addr.String())
  node.mutex.Unlock()
  return err
}

func (node *Node) ClosePeerForce(addr *net.UDPAddr) {
  node.mutex.Lock()
  conn, ok := node.ipToConnection[addr.String()]
  if ok {
    close(conn.consumableBuffer)
    delete(node.ipToConnection, addr.String())
  }
  node.mutex.Unlock()
}

func (node *Node) Shutdown() {
  node.mutex.Lock()
  for _, conn := range node.ipToConnection {
    close(conn.consumableBuffer)
  }
  node.ipToConnection = make(map[string]*EncryptedConnection)
  node.mutex.Unlock()
  for len(node.runErrors) > 0 {
    <-node.runErrors
  }
  node.stopChan <- struct{}{}
  node.udpConn.Close()
  close(node.stopChan)
  close(node.incomingConnection)
  close(node.runErrors)
}

func (node *Node) Connect(ctx context.Context, addr *net.UDPAddr) error {
  node.mutex.RLock()
  if _, ok := node.ipToConnection[addr.String()]; ok {
    node.mutex.RUnlock()
    return errors.New("Connection already established")
  }
  handshake, ok := node.ipToHandshake[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    handshake = NewHandshake()
    node.mutex.Lock()
    node.ipToHandshake[addr.String()] = handshake
    node.mutex.Unlock()
  }
  hello := &Hello{
    PublicKeyDH: [32]byte(handshake.publicKeyDH.Bytes()),
    PublicKeyED: [32]byte(node.localPublicKeyED),
    Signature: [64]byte(ed25519.Sign(node.localPrivateKeyED, append(handshake.publicKeyDH.Bytes(), node.localPublicKeyED...))),
  }
  bytesToSend := make([]byte, hello.BufferSize())
  n, err := hello.Serialize(bytesToSend)
  if err != nil {
    return err
  }
  _, err = node.udpConn.WriteToUDP(bytesToSend[:n], addr)
  if err != nil {
    return err
  }
  for node.IsConnected(addr) == false {
    select {
    case <-ctx.Done():
      return errors.New("Context cancelled")
    case err := <-node.runErrors:
      return err
    default:
      runtime.Gosched()
    }
  }
  return nil
}

func (node *Node) Accept(ctx context.Context) (*net.UDPAddr, error) {
  select {
  case <-ctx.Done():
    return nil, errors.New("Context cancelled")
  case err := <-node.runErrors:
    return nil, err
  case incoming, ok := <-node.incomingConnection:
    if !ok {
      return nil, errors.New("Channel closed")
    }
    helloReply := &Hello{
      PublicKeyDH: [PublicKeyDHSize]byte(incoming.publicKeyDH),
      PublicKeyED: [PublicKeyEDSize]byte(node.localPublicKeyED),
      Signature: [SignatureSize]byte(ed25519.Sign(node.localPrivateKeyED, append(incoming.publicKeyDH, node.localPublicKeyED...))),
    }
    bytesToSend := make([]byte, helloReply.BufferSize())
    n, err := helloReply.Serialize(bytesToSend)
    if err != nil {
      return nil, err
    }
    _, err = node.udpConn.WriteToUDP(bytesToSend[:n], incoming.addr)
    if err != nil {
      return nil, err
    }
    connection := NewEncryptedConnection(incoming.addr, incoming.publicKeyED[:], incoming.aesSecret)
    node.mutex.Lock()
    node.ipToConnection[incoming.addr.String()] = connection
    node.mutex.Unlock()
    return incoming.addr, nil
  }
}

func (node *Node) ConnectViaPeer(ctx context.Context, addr *net.UDPAddr, intermediate *net.UDPAddr) error {
  node.mutex.RLock()
  if _, ok := node.ipToConnection[addr.String()]; ok {
    node.mutex.RUnlock()
    return errors.New("Connection already established")
  }
  conn, ok := node.ipToConnection[intermediate.String()]
  node.mutex.RUnlock()
  if !ok {
    return errors.New("Connection not established")
  }
  handshake := NewHandshake()

  node.mutex.Lock()
  node.ipToHandshake[addr.String()] = handshake
  node.mutex.Unlock()
  intro := &Introduction{
    Flags: 0,
    IP: [16]byte(addr.IP.To16()),
    Port: uint16(addr.Port),
    PublicKeyDH: [PublicKeyDHSize]byte(handshake.publicKeyDH.Bytes()),
    PublicKeyED: [PublicKeyEDSize]byte(node.localPublicKeyED),
    Signature: [SignatureSize]byte(ed25519.Sign(node.localPrivateKeyED, append(handshake.publicKeyDH.Bytes(), node.localPublicKeyED...))),
  }
  packets := conn.txStream.Add([]Packet{intro})
  if packets == nil {
    return nil
  }
  bytesToSend := SerializePackets(packets)
  for _, b := range bytesToSend {
    conn.encrypt(b, b)
    _, err := node.udpConn.WriteToUDP(b, intermediate)
    if err != nil {
      return err
    }
  }
  for node.IsConnected(addr) == false {
    select {
    case <-ctx.Done():
      return errors.New("Context cancelled")
    case err := <-node.runErrors:
      return err
    default:
      runtime.Gosched()
    }
  }
  return nil
}

func (node *Node) IsConnected(addr *net.UDPAddr) bool {
  node.mutex.RLock()
  _, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  return ok
}

func (node *Node) GetPeerPublicKey(addr *net.UDPAddr) ([]byte, error) {
  node.mutex.RLock()
  connection, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if ok {
    return connection.peerPublicKeyED, nil
  }
  return nil, errors.New("Connection not established")
}

func (node *Node) Recv(ctx context.Context, addr *net.UDPAddr) ([]byte, byte, error) {
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    return nil, 0, errors.New("Connection not established")
  }
  select {
  case <-ctx.Done():
    return nil, 0, errors.New("Context cancelled")
  case err := <-node.runErrors:
    return nil, 0, err
  case consumable, ok := <-conn.consumableBuffer:
    if !ok {
      return nil, 0, errors.New("Channel closed")
    }
    return consumable.buffer, consumable.streamID, conn.tryAck(consumable.streamID, node.udpConn)
  }
}

func (node *Node) Ack(addr *net.UDPAddr, streamID byte) error {
  select {
  case err := <-node.runErrors:
    return err
  default:
    node.mutex.RLock()
    conn, ok := node.ipToConnection[addr.String()]
    node.mutex.RUnlock()
    if !ok {
      return errors.New("Connection not established")
    }
    return conn.ack(streamID, node.udpConn)   
  }
}

func (node *Node) Send(data []byte, addr *net.UDPAddr, streamID byte) error {
  select {
  case err := <- node.runErrors:
    return err
  default:
    node.mutex.RLock()
    conn, ok := node.ipToConnection[addr.String()]
    node.mutex.RUnlock()
    if !ok {
      return errors.New("Connection not established")
    }
    return conn.onSend(data, streamID, node.udpConn)   
  }
}

func (node *Node) run() error {
  buf := make([]byte, MaxPacketSize)
  n, addr, err := node.udpConn.ReadFromUDP(buf)
  if err != nil {
    return err
  }
  node.mutex.RLock()
  connection, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if ok {
    return node.handleConnection(addr, buf[:n], connection)
  }
  node.mutex.RLock()
  handshake, ok := node.ipToHandshake[addr.String()]
  node.mutex.RUnlock()
  if ok {
    return node.handleHandshake(addr, buf[:n], handshake)
  }
  return node.handleDefault(addr, buf[:n])
}

func (node *Node) handleDefault(addr *net.UDPAddr, buf []byte) error {
  packet, _, err := DeserializePacket(buf)
  if err != nil {
    return err
  }
  if packet.Type() != PacketHello {
    return errors.New("Invalid packet type")
  }
  hello := packet.(*Hello)
  cookie := computeCookie(hello.PublicKeyDH[:], hello.PublicKeyED[:], hello.Signature[:], node.randomSecret)
  if hello.Cookie != cookie {
    if !verifyHello(hello.PublicKeyDH[:], hello.PublicKeyED[:], hello.Signature[:]) {
      return nil
    }
    retry := &HelloRetry{
      Cookie: cookie,
    }
    buf := make([]byte, retry.BufferSize())
    _, err := retry.Serialize(buf)
    if err != nil {
      return err
    }
    _, err = node.udpConn.WriteToUDP(buf, addr)
    return err
  }
  publicKeyDH, err := ecdh.X25519().NewPublicKey(hello.PublicKeyDH[:])
  if err != nil {
    return err
  }
  localPrivateKeyDH, err := ecdh.X25519().GenerateKey(rand.Reader)
  if err != nil {
    return err
  }
  aesSecret, err := localPrivateKeyDH.ECDH(publicKeyDH)
  if err != nil {
    return err
  }
  node.incomingConnection <- incomingConnectionInfo{
    addr: addr,
    publicKeyED: hello.PublicKeyED[:],
    aesSecret: aesSecret,
    publicKeyDH: localPrivateKeyDH.PublicKey().Bytes(),
  }
  return nil
}

func (node *Node) handleHandshake(addr *net.UDPAddr, buf []byte, handshake *Handshake) error {
  packet, _, err := DeserializePacket(buf)
  if err != nil {
    return err
  }
  switch packet.Type() {
  case PacketHello:
    hello := packet.(*Hello)
    encryptedConnection, err := handshake.onHello(hello, addr)
    if err != nil {
      return err
    }
    node.mutex.Lock()
    node.ipToConnection[addr.String()] = encryptedConnection
    delete(node.ipToHandshake, addr.String())
    node.mutex.Unlock()
  case PacketHelloRetry:
    helloRetry := packet.(*HelloRetry)
    node.mutex.Lock()
    defer node.mutex.Unlock()
    err := handshake.onHelloRetry(helloRetry, addr, node.udpConn, node.localPrivateKeyED, node.localPublicKeyED)
    if err != nil {
      return err
    }
  default:
    return errors.New("Invalid packet type")
  }
  return nil
}

func (node *Node) handleConnection(addr *net.UDPAddr, buf []byte, conn *EncryptedConnection) error {
  err := conn.decrypt(buf, buf)
  if err != nil {
    return err
  }
  packets, err := DeserializePackets(buf)
  if err != nil {
    return err
  }
  for _, packet := range packets {
    switch packet.Type() {
    case PacketData:
      data := packet.(*Data)
      closed, err := conn.onData(data, node.udpConn)
      if err != nil {
	return err
      }
      if closed {
	close(conn.consumableBuffer)
	node.mutex.Lock()
	delete(node.ipToConnection, addr.String())
	node.mutex.Unlock()
      }
    case PacketIntroduction:
      intro := packet.(*Introduction)
      err := node.handleIntroduction(intro, addr)
      if err != nil {
	return err
      }
    default:
      return errors.New("Invalid packet type")
    }
  }
  return nil
}

func (node *Node) handleIntroduction(intro *Introduction, source *net.UDPAddr) error {
  addr := &net.UDPAddr{
    IP: intro.IP[:],
    Port: int(intro.Port),
  }
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if intro.Flags & IntroductionIsSourceAddress != 0 {
    if ok {
      return errors.New("Connection already established")
    }
    _, ok := node.ipToHandshake[addr.String()]
    if ok {
      return errors.New("Handshake already in progress")
    }
    if !verifyHello(intro.PublicKeyDH[:], intro.PublicKeyED[:], intro.Signature[:]) {
      return errors.New("Invalid signature")
    }
    cookie := computeCookie(intro.PublicKeyDH[:], intro.PublicKeyED[:], intro.Signature[:], node.randomSecret)
    helloRetry := &HelloRetry{
      Cookie: cookie,
    }
    buf := make([]byte, helloRetry.BufferSize())
    _, err := helloRetry.Serialize(buf)
    if err != nil {
      return err
    }
    _, err = node.udpConn.WriteToUDP(buf, addr)
    if err != nil {
      return err
    }
    return nil
  }
  if !ok {
    return errors.New("unknown destination address")
  }
  intro.Flags |= IntroductionIsSourceAddress
  intro.IP = [16]byte(source.IP.To16())
  intro.Port = uint16(source.Port)
  packets := conn.txStream.Add([]Packet{intro})
  if packets == nil {
    return nil
  }
  bytesToSend := SerializePackets(packets)
  for _, b := range bytesToSend {
    conn.encrypt(b, b)
    _, err := node.udpConn.WriteToUDP(b, addr)
    if err != nil {
      return err
    }
  }
  return nil
}

