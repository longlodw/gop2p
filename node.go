// Package gop2p provides a simple API for establishing encrypted peer-to-peer connections over UDP.
// Each node may have multiple connections with other nodes, each connection may have multiple streams.
// gop2p uses udp6 for all connections, with reliable transmission and encryption on each stream.
//
// Example usage:
//
//	node, err := NewNode(localPrivateKeyED, localPublicKeyED, udpAddr)
//	if err != nil {
//	  log.Fatal(err)
//	}
//	defer node.Shutdown()
//	ctx, cancel := context.WithTimeout(context.Background(), 5 * time.Second)
//	defer cancel()
//	peerAddr, err := node.AcceptPeer(ctx)
//	if err != nil {
//	  log.Fatal(err)
//	}
//	defer node.ClosePeer(peerAddr)
//	streamID, err := node.AcceptStream(ctx, peerAddr)
//	if err != nil {
//	  log.Fatal(err)
//	}
//	defer node.CloseStream(peerAddr, streamID)
//	buf := make([]byte, 1024)
//	n, err := node.Recv(ctx, buf, peerAddr, streamID)
//	if err != nil {
//	  log.Fatal(err)
//	}
//	_, err = node.Send(ctx, []byte("Hello"), peerAddr, streamID)
//	if err != nil {
//	  log.Fatal(err)
//	}
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

// Node represents a peer-to-peer node.
// It is used to establish encrypted connections with other nodes.
type Node struct {
  randomSecret []byte
  localPublicKeyED []byte
  localPrivateKeyED []byte
  udpConn *net.UDPConn
  ipToConnection map[string]*peerConnection
  ipToHandshake map[string]*handshake
  mutex sync.RWMutex
  incomingConnection chan incomingConnectionInfo
  runErrors chan error
  stopChan chan struct{}
  maxStreamQueue int
}

type incomingConnectionInfo struct {
  addr *net.UDPAddr
  publicKeyED []byte
  aesSecret []byte
  publicKeyDH []byte
}

// NewNode creates a new Node.
func NewNode(localPrivateKeyED []byte, localPublicKeyED []byte, udpAddr *net.UDPAddr, maxConnectionQueue int, maxStreamQueue int) (*Node, error) {
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
    ipToConnection: make(map[string]*peerConnection),
    ipToHandshake: make(map[string]*handshake),
    incomingConnection: make(chan incomingConnectionInfo, maxConnectionQueue),
    runErrors: make(chan error),
    stopChan: make(chan struct{}),
    maxStreamQueue: maxStreamQueue,
  }
  go func() {
    for {
      select {
      case <-node.stopChan:
	return
      default:
	node.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	err := node.run()
	if err == nil {
	  continue
	}
	timeoutErr, ok := err.(net.Error)
	if ok && timeoutErr.Timeout() {
	  continue
	}
	_, ok = err.(InvalidPacketError)
	if ok {
	  continue
	}
	node.runErrors <- err
      }
    }
  }()
  return node, nil
}

// CloseStream closes a stream with a peer.
func (node *Node) CloseStream(addr *net.UDPAddr, streamID byte) error {
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    return newPeerConnectionNotEstablishedError(addr.String())
  }
  p := conn.closeStream(streamID)
  if p == nil {
    return nil
  }
  return conn.sendPackets([]packet{p}, node.udpConn)
}

// ClosePeer gracefully closes a connection with a peer.
func (node *Node) ClosePeer(addr *net.UDPAddr) error {
  node.mutex.Lock()
  defer node.mutex.Unlock()
  conn, ok := node.ipToConnection[addr.String()]
  if !ok {
    return newPeerConnectionNotEstablishedError(addr.String())
  }
  err := conn.close(node.udpConn)
  delete(node.ipToConnection, addr.String())
  return err
}

// Shutdown closes all connections and stops the node.
func (node *Node) Shutdown() {
  node.mutex.Lock()
  for _, conn := range node.ipToConnection {
    conn.close(node.udpConn)
  }
  node.ipToConnection = make(map[string]*peerConnection)
  node.mutex.Unlock()
  for len(node.runErrors) > 0 {
    <-node.runErrors
  }
  node.stopChan <- struct{}{}
  close(node.stopChan)
  node.udpConn.Close()
  close(node.incomingConnection)
  close(node.runErrors)
}

// ConnectPeer establishes a connection with a peer.
func (node *Node) ConnectPeer(ctx context.Context, addr *net.UDPAddr) error {
  node.mutex.RLock()
  if _, ok := node.ipToConnection[addr.String()]; ok {
    node.mutex.RUnlock()
    return newConnectionAlreadyEstablishedError(addr.String())
  }
  handshake, ok := node.ipToHandshake[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    handshake = newHandshake(node.maxStreamQueue)
    node.mutex.Lock()
    node.ipToHandshake[addr.String()] = handshake
    node.mutex.Unlock()
  }
  hello := &hello{
    publicKeyDH: [32]byte(handshake.publicKeyDH.Bytes()),
    publicKeyED: [32]byte(node.localPublicKeyED),
    signature: [64]byte(ed25519.Sign(node.localPrivateKeyED, append(handshake.publicKeyDH.Bytes(), node.localPublicKeyED...))),
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
      return newCancelledError()
    case err := <-node.runErrors:
      return err
    default:
      runtime.Gosched()
    }
  }
  return nil
}

// AcceptPeer waits for a connection from a peer, returns the peer's address and error.
func (node *Node) AcceptPeer(ctx context.Context) (*net.UDPAddr, error) {
  select {
  case <-ctx.Done():
    return nil, newCancelledError()
  case err := <-node.runErrors:
    return nil, err
  case incoming, ok := <-node.incomingConnection:
    if !ok {
      return nil, newChannelClosedError()
    }
    helloReply := &hello{
      publicKeyDH: [PublicKeyDHSize]byte(incoming.publicKeyDH),
      publicKeyED: [PublicKeyEDSize]byte(node.localPublicKeyED),
      signature: [SignatureSize]byte(ed25519.Sign(node.localPrivateKeyED, append(incoming.publicKeyDH, node.localPublicKeyED...))),
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
    connection := newPeerConnection(incoming.addr, incoming.publicKeyED[:], incoming.aesSecret, node.maxStreamQueue)
    node.mutex.Lock()
    node.ipToConnection[incoming.addr.String()] = connection
    node.mutex.Unlock()
    return incoming.addr, nil
  }
}

// AcceptStream waits for a stream opened from a peer, returns the stream ID and an error.
func (node *Node) AcceptStream(ctx context.Context, addr *net.UDPAddr) (byte, error) {
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    return 0, newPeerConnectionNotEstablishedError(addr.String())
  }
  select {
  case <-ctx.Done():
    return 0, newCancelledError()
  case err := <-node.runErrors:
    return 0, err
  case incoming, ok := <-conn.incomingStream:
    if !ok {
      return 0, newChannelClosedError()
    }
    return incoming, nil
  }
}

// OpenStream opens a stream with a peer.
func (node *Node) ConnectStream(addr *net.UDPAddr, streamID byte) error {
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    return newPeerConnectionNotEstablishedError(addr.String())
  }
  conn.rwMutex.Lock()
  defer conn.rwMutex.Unlock()
  _, ok = conn.streams[streamID]
  if ok {
    return newStreamAlreadyEstablishedError(streamID)
  }
  conn.streams[streamID] = newStream(streamID)
  return nil
}

// ConnectPeerViaPeer establishes a connection with a peer through an intermediate peer.
func (node *Node) ConnectPeerViaPeer(ctx context.Context, addr *net.UDPAddr, intermediate *net.UDPAddr) error {
  node.mutex.RLock()
  if _, ok := node.ipToConnection[addr.String()]; ok {
    node.mutex.RUnlock()
    return newConnectionAlreadyEstablishedError(addr.String())
  }
  conn, ok := node.ipToConnection[intermediate.String()]
  node.mutex.RUnlock()
  if !ok {
    return newPeerConnectionNotEstablishedError(intermediate.String())
  }
  handshake := newHandshake(node.maxStreamQueue)

  node.mutex.Lock()
  node.ipToHandshake[addr.String()] = handshake
  node.mutex.Unlock()
  intro := &introduction{
    flags: 0,
    ip: [16]byte(addr.IP.To16()),
    port: uint16(addr.Port),
    publicKeyDH: [PublicKeyDHSize]byte(handshake.publicKeyDH.Bytes()),
    publicKeyED: [PublicKeyEDSize]byte(node.localPublicKeyED),
    signature: [SignatureSize]byte(ed25519.Sign(node.localPrivateKeyED, append(handshake.publicKeyDH.Bytes(), node.localPublicKeyED...))),
  }
  err := conn.sendPackets([]packet{intro}, node.udpConn)
  if err != nil {
    return err
  }
  for node.IsConnected(addr) == false {
    select {
    case <-ctx.Done():
      return newCancelledError()
    case err := <-node.runErrors:
      return err
    default:
      runtime.Gosched()
    }
  }
  return nil
}

// IsConnected returns true if a connection with a peer is established.
func (node *Node) IsConnected(addr *net.UDPAddr) bool {
  node.mutex.RLock()
  _, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  return ok
}

// GetPeerPublicKey returns the public key of a peer.
func (node *Node) GetPeerPublicKey(addr *net.UDPAddr) ([]byte, error) {
  node.mutex.RLock()
  connection, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if ok {
    return connection.peerPublicKeyED, nil
  }
  return nil, newPeerConnectionNotEstablishedError(addr.String())
}

// Recv receives data from a specific peer, returns the data, stream ID and an error.
func (node *Node) Recv(ctx context.Context, buf []byte, addr *net.UDPAddr, streamID byte) (int, error) {
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if !ok {
    return -1, newPeerConnectionNotEstablishedError(addr.String())
  }

  for {
    select {
    case <-ctx.Done():
      return -1, newCancelledError()
    case err := <-node.runErrors:
      return -1, err
    default:
      n, consumed, err := conn.consume(buf, streamID, node.udpConn)
      if err != nil || consumed {
	return n, err
      }
      runtime.Gosched()
    }
  }
}

// Ack sends an acknowledgment to a peer on a specific stream, which should promt the peer to send more data.
func (node *Node) Ack(addr *net.UDPAddr, streamID byte) error {
  select {
  case err := <-node.runErrors:
    return err
  default:
    node.mutex.RLock()
    conn, ok := node.ipToConnection[addr.String()]
    node.mutex.RUnlock()
    if !ok {
      return newPeerConnectionNotEstablishedError(addr.String())
    }
    return conn.ack(streamID, node.udpConn)   
  }
}

// Send sends data to a specific peer on a specific channel, which must be opened or accepted before, returns number of bytes sent and an error.
func (node *Node) Send(ctx context.Context, data []byte, addr *net.UDPAddr, streamID byte) (int, error) {
  l := 0
  originalDataLen := len(data)
  for {
    select {
    case <-ctx.Done():
      return l, newCancelledError()
    case err := <- node.runErrors:
      return l, err
    default:
      node.mutex.RLock()
      conn, ok := node.ipToConnection[addr.String()]
      node.mutex.RUnlock()
      if !ok {
	return l, newPeerConnectionNotEstablishedError(addr.String())
      }
      n, err := conn.onSend(data, streamID, node.udpConn)
      l += n
      if err != nil || l == originalDataLen {
	return l, err
      }
      if l != len(data) {
	data = data[l:]
	runtime.Gosched()
	continue
      }
    }
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
  pac, _, err := deserializePacket(buf)
  if err != nil {
    return err
  }
  if pac.Type() != PacketHello {
    return newInvalidPacketError("Expected hello packet")
  }
  hello := pac.(*hello)
  cookie := computeCookie(hello.publicKeyDH[:], hello.publicKeyED[:], hello.signature[:], node.randomSecret)
  if hello.cookie != cookie {
    if !verifyHello(hello.publicKeyDH[:], hello.publicKeyED[:], hello.signature[:]) {
      return newInvalidPacketError("Invalid signature")
    }
    retry := &helloRetry{
      cookie: cookie,
    }
    buf := make([]byte, retry.BufferSize())
    _, err := retry.Serialize(buf)
    if err != nil {
      return err
    }
    _, err = node.udpConn.WriteToUDP(buf, addr)
    return err
  }
  publicKeyDH, err := ecdh.X25519().NewPublicKey(hello.publicKeyDH[:])
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
    publicKeyED: hello.publicKeyED[:],
    aesSecret: aesSecret,
    publicKeyDH: localPrivateKeyDH.PublicKey().Bytes(),
  }
  return nil
}

func (node *Node) handleHandshake(addr *net.UDPAddr, buf []byte, handshake *handshake) error {
  packet, _, err := deserializePacket(buf)
  if err != nil {
    return err
  }
  switch packet.Type() {
  case PacketHello:
    hello := packet.(*hello)
    peerConnection, err := handshake.onHello(hello, addr)
    if err != nil {
      return err
    }
    node.mutex.Lock()
    node.ipToConnection[addr.String()] = peerConnection
    delete(node.ipToHandshake, addr.String())
    node.mutex.Unlock()
  case PacketHelloRetry:
    helloRetry := packet.(*helloRetry)
    node.mutex.Lock()
    defer node.mutex.Unlock()
    err := handshake.onHelloRetry(helloRetry, addr, node.udpConn, node.localPrivateKeyED, node.localPublicKeyED)
    if err != nil {
      return err
    }
  default:
    return newInvalidPacketError("Expected hello or hello retry packet")
  }
  return nil
}

func (node *Node) handleConnection(addr *net.UDPAddr, buf []byte, conn *peerConnection) error {
  err := conn.decrypt(buf, buf)
  if err != nil {
    return err
  }
  packets, err := deserializePackets(buf)
  if err != nil {
    return err
  }
  for _, packet := range packets {
    switch packet.Type() {
    case PacketData:
      data := packet.(*data)
      err := conn.onData(data, node.udpConn)
      if err != nil {
	return err
      }
    case PacketIntroduction:
      intro := packet.(*introduction)
      err := node.handleIntroduction(intro, addr)
      if err != nil {
	return err
      }
    case PacketConnectionClosed:
      node.mutex.Lock()
      delete(node.ipToConnection, addr.String())
      node.mutex.Unlock()
      err := conn.close(node.udpConn)
      if err !=	nil {
	return err
      }
    default:
      return newInvalidPacketError("Expected data or introduction packet")
    }
  }
  return nil
}

func (node *Node) handleIntroduction(intro *introduction, source *net.UDPAddr) error {
  addr := &net.UDPAddr{
    IP: intro.ip[:],
    Port: int(intro.port),
  }
  node.mutex.RLock()
  conn, ok := node.ipToConnection[addr.String()]
  node.mutex.RUnlock()
  if intro.flags & IntroductionIsSourceAddress != 0 {
    if ok {
      return newInvalidPacketError("Connection already established")
    }
    _, ok := node.ipToHandshake[addr.String()]
    if ok {
      return newInvalidPacketError("Unknown address")
    }
    if !verifyHello(intro.publicKeyDH[:], intro.publicKeyED[:], intro.signature[:]) {
      return newInvalidPacketError("Invalid signature")
    }
    cookie := computeCookie(intro.publicKeyDH[:], intro.publicKeyED[:], intro.signature[:], node.randomSecret)
    helloRetry := &helloRetry{
      cookie: cookie,
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
    return newInvalidPacketError("Connection not established")
  }
  intro.flags |= IntroductionIsSourceAddress
  intro.ip = [16]byte(source.IP.To16())
  intro.port = uint16(source.Port)
  packets := conn.txStream.add([]packet{intro})
  if packets == nil {
    return nil
  }
  bytesToSend := serializePackets(packets)
  for _, b := range bytesToSend {
    conn.encrypt(b, b)
    _, err := node.udpConn.WriteToUDP(b, addr)
    if err != nil {
      return err
    }
  }
  return nil
}

