package v0

import (
	"errors"
	"net"
	"sync"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/ed25519"
)

type Node struct {
  randomSecret []byte
  localPublicKeyED []byte
  localPrivateKeyED []byte
  udpConn *net.UDPConn
  ipToConnection map[string]*EncryptedConnection
  ipToHandshake map[string]*Handshake
  mutex sync.RWMutex
  consumableBuffer chan consumable
}

type consumable struct {
  buffer []byte
  addr *net.UDPAddr
  streamID byte
}

func (node *Node) NewNode(localPrivateKeyED []byte, localPublicKeyED []byte, udpConn *net.UDPConn) *Node {
  randomSecret := make([]byte, 32)
  n, err := rand.Read(randomSecret)
  if err != nil {
    return nil
  }
  if n != 32 {
    return nil
  }
  return &Node{
    randomSecret: randomSecret,
    localPublicKeyED: localPublicKeyED,
    localPrivateKeyED: localPrivateKeyED,
    udpConn: udpConn,
    ipToConnection: make(map[string]*EncryptedConnection),
    ipToHandshake: make(map[string]*Handshake),
    consumableBuffer: make(chan consumable),
  }
}

func (node *Node) Connect(addr *net.UDPAddr) error {
  node.mutex.RLock()
  if _, ok := node.ipToConnection[addr.String()]; ok {
    node.mutex.RUnlock()
    return errors.New("Connection already established")
  }
  handshake, ok := node.ipToHandshake[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    handshake = NewHandshake()
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
  return nil
}

func (node *Node) ConnectViaPeer(addr *net.UDPAddr, intermediate *net.UDPAddr) error {
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
    PublicKeyDH: [32]byte(handshake.publicKeyDH.Bytes()),
    PublicKeyED: [32]byte(node.localPublicKeyED),
    Signature: [64]byte(ed25519.Sign(node.localPrivateKeyED, append(handshake.publicKeyDH.Bytes(), node.localPublicKeyED...))),
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
  return nil
}

func (node *Node) GetPeerPublicKey(addr *net.UDPAddr) ([]byte, error) {
  node.mutex.RLock()
  connection, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if ok {
    return connection.peerPublicKeyED, nil
  }
  return nil, errors.New("No connection")
}

func (node *Node) Recv() ([]byte, *net.UDPAddr, byte, error) {
  for {
    select {
    case consumable, ok := <-node.consumableBuffer:
      if !ok {
	return nil, nil, 0, errors.New("Channel closed")
      }
      node.mutex.RLock()
      conn, ok := node.ipToConnection[consumable.addr.String()]
      node.mutex.RUnlock()
      if !ok {
	return consumable.buffer, consumable.addr, consumable.streamID, nil
      }
      return consumable.buffer, consumable.addr, consumable.streamID, conn.tryAck(consumable.streamID, node.udpConn)
    default:
      err := node.run()
      if err != nil {
	return nil, nil, 0, err
      }
    }
  }
}

func (node *Node) Ack(addr *net.UDPAddr, streamID byte) error {
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    return errors.New("Connection not established")
  }
  return conn.ack(streamID, node.udpConn)
}

func (node *Node) Send(data []byte, addr *net.UDPAddr, streamID byte) error {
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    return errors.New("Connection not established")
  }
  return conn.onSend(data, streamID, node.udpConn)
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
  localPrivateKeyED, err := ecdh.X25519().NewPrivateKey(node.localPrivateKeyED)
  aesSecret, err := localPrivateKeyED.ECDH(publicKeyDH)
  if err != nil {
    return err
  }
  connection := NewEncryptedConnection(addr, hello.PublicKeyED[:], aesSecret)
  node.mutex.Lock()
  node.ipToConnection[addr.String()] = connection
  node.mutex.Unlock()
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
    err := handshake.onHello(hello, addr, &node.ipToConnection, &node.ipToHandshake)
    if err != nil {
      return err
    }
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
      closed, consumableBuffer, err := conn.onData(data, nil, node.udpConn)
      if err != nil {
	return err
      }
      if closed {
	node.mutex.Lock()
	delete(node.ipToConnection, addr.String())
	node.mutex.Unlock()
      }
      if consumableBuffer != nil {
	node.consumableBuffer <- consumable{
	  buffer: consumableBuffer,
	  addr: addr,
	  streamID: data.StreamID,
	}
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
  intro.Flags &= IntroductionIsSourceAddress
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
