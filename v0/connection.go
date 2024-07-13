package v0

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"
)

type Connection struct {
  randomSecret []byte
  addr *net.UDPAddr
  peerPublicKeyED []byte
  localPublicKeyED []byte
  localPrivateKeyED []byte
  secretAES []byte
  streamIDToChannel map[byte]*Channel
  txStream *MergeStream[Packet]
  rwMutex sync.RWMutex
  router *Router
  udpConn *net.UDPConn
}

func NewConnection(randomSecret []byte, addr *net.UDPAddr, peerPublicKeyED []byte, localPublicKeyED []byte, localPrivateKeyED []byte, secretAES []byte, router *Router, udpConn *net.UDPConn) *Connection {
  return &Connection{
    randomSecret: randomSecret,
    addr: addr,
    peerPublicKeyED: peerPublicKeyED,
    localPublicKeyED: localPublicKeyED,
    localPrivateKeyED: localPrivateKeyED,
    secretAES: secretAES,
    streamIDToChannel: make(map[byte]*Channel),
    txStream: NewMergeStream[Packet](),
    rwMutex: sync.RWMutex{},
    router: router,
    udpConn: udpConn,
  }
}

func (connection *Connection) encrypt(des []byte, plain []byte) error {
  block, err := aes.NewCipher(connection.secretAES)
  if err != nil {
    return err
  }
  block.Encrypt(des, plain)
  return nil
}

func (connection *Connection) decrypt(des []byte, cipher []byte) error {
  block, err := aes.NewCipher(connection.secretAES)
  if err != nil {
    return err
  }
  block.Decrypt(des, cipher)
  return nil
}

func (connection *Connection) Introduce(addr *net.UDPAddr, publicKeyED []byte) error {
  privateKeyDH, err := ecdh.X25519().GenerateKey(rand.Reader)
  if err != nil {
    return err
  }
  publicKeyDH := privateKeyDH.PublicKey()
  signature := ed25519.Sign(connection.localPrivateKeyED, append(publicKeyED, publicKeyDH.Bytes()...))
  handShake := &Handshake{
    randomSecret: connection.randomSecret,
    localPublicKeyED: connection.localPublicKeyED,
    localPrivateKeyED: connection.localPrivateKeyED,
    peerPublicKeyED: publicKeyED,
    privateKeyDH: privateKeyDH,
    publicKeyDH: publicKeyDH,
  }
  introduction := &Introduction{
    PublicKeyDH: [32]byte(publicKeyDH.Bytes()),
    SourcePublicKeyED: [32]byte(connection.localPublicKeyED),
    SourceIP: [16]byte(connection.addr.IP.To16()),
    SourcePort: uint16(connection.addr.Port),
    TargetPublicKeyED: [32]byte(publicKeyED),
    Signature: [64]byte(signature),
  }
  _, err = connection.udpConn.WriteToUDP([]byte{0}, addr)
  if err != nil {
    return err
  }
  packets := connection.txStream.Add([]Packet{introduction})
  if packets != nil {
    bytesTransaction := connection.PacketTransactionToBytesTransaction(&Transaction[Packet]{Chunks: packets, Des: &Identifier{Address: connection.addr, PublicKeyED: connection.peerPublicKeyED}})
    err := sendTransactionBytes(connection.udpConn, bytesTransaction)
    if err != nil {
      return err
    }
  }
  connection.router.mutex.Lock()
  connection.router.ipToHandler[addr.String()] = handShake
  connection.router.mutex.Unlock()
  return nil
}

func (connection *Connection) Recv(id byte, buffer []byte) (int, error) {
  connection.rwMutex.RLock()
  channel, ok := connection.streamIDToChannel[id]
  connection.rwMutex.RUnlock()
  if !ok {
    return -1, errors.New("Channel not found")
  }
  n := channel.ConsumeRx(buffer)
  if n != -1 {
    return n, nil
  }
  packet := &Data{
    StreamID: id,
    SequenceNumber: channel.sequenceNumber,
    DataType: DataAck,
    AckNumber: channel.ackNumber,
    Data: make([]byte, 0),
  }
  packets := connection.txStream.Add([]Packet{packet})
  if packets != nil {
    bytesTransaction := connection.PacketTransactionToBytesTransaction(&Transaction[Packet]{Chunks: packets, Des: &Identifier{Address: connection.addr, PublicKeyED: connection.peerPublicKeyED}})
    err := sendTransactionBytes(connection.udpConn, bytesTransaction)
    if err != nil {
      return -1, err
    }
  }
  for {
    err := connection.router.ingest(connection.udpConn)
    if err != nil {
      return -1, err
    }
    n := channel.ConsumeRx(buffer)
    if n != -1 {
      return n, nil
    }
  }
}

func (connection *Connection) Send(id byte, data []byte) (int, error) {
  connection.rwMutex.RLock()
  channel, ok := connection.streamIDToChannel[id]
  connection.rwMutex.RUnlock()
  if !ok {
    channel = NewChannel(connection, id)
    connection.rwMutex.Lock()
    connection.streamIDToChannel[id] = channel
    connection.rwMutex.Unlock()
  }
  segs := segments(data)
  packets := make([]Packet, len(segs))
  channel.mutex.Lock()
  defer channel.mutex.Unlock()
  for i, seg := range segs {
    packets[i] = &Data{
      StreamID: id,
      Data: seg,
      SequenceNumber: channel.sequenceNumber,
      DataType: 0,
    }
    channel.sequenceNumber += 1
  }
  if channel.needAck {
    packets[0].(*Data).DataType |= DataAck
    channel.needAck = false
    packets[0].(*Data).AckNumber = channel.ackNumber
  }
  bytesTransaction := connection.PacketTransactionToBytesTransaction(&Transaction[Packet]{Chunks: packets, Des: &Identifier{Address: connection.addr, PublicKeyED: connection.peerPublicKeyED}})
  err := sendTransactionBytes(connection.udpConn, bytesTransaction)
  if err != nil {
    return -1, err
  }
  return len(data), nil
}

func (connection *Connection) OnPacket(packet Packet, source *Identifier) (PacketsHandler, *Transaction[Packet], error) {
  switch packet.Type() {
  case PacketIntroduction:
    connection.onIntroduction(packet.(*Introduction), source)
  case PacketData:
    connection.onData(packet, source)
  }
  return nil, nil, errors.New("Invalid packet type")
}

func (connection *Connection) Serialize(packets *Transaction[Packet]) *Transaction[[]byte] {
  sp := DefaultPacketSerialize(packets)
  if sp == nil {
    return nil
  }
  for _, packet := range sp.Chunks {
    connection.encrypt(packet, packet)
  }
  return sp
}

func (connection *Connection) Deserialize(buf []byte) *Transaction[Packet] {
  connection.decrypt(buf, buf)
  packets := make([]Packet, 0)
  for len(buf) > 0 {
    packet, n, err := DeserializePacket(buf)
    if err != nil {
      return &Transaction[Packet]{Des: &Identifier{PublicKeyED: connection.peerPublicKeyED, Address: connection.addr}, Chunks: packets}
    }
    packets = append(packets, packet)
    buf = buf[n:]
  }
  return &Transaction[Packet]{Des: &Identifier{PublicKeyED: connection.peerPublicKeyED, Address: connection.addr}, Chunks: packets}
}

func (connection *Connection) onIntroduction(packet *Introduction, source *Identifier) (PacketsHandler, *Transaction[Packet], error) {
  if bytes.Equal(packet.TargetPublicKeyED[:], connection.peerPublicKeyED) {
    return nil, &Transaction[Packet]{Chunks: []Packet{packet}, Des: &Identifier{Address: connection.addr, PublicKeyED: connection.peerPublicKeyED}}, nil
  }
  if bytes.Equal(packet.TargetPublicKeyED[:], connection.localPublicKeyED) {
    privateKeyDH, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil {
      return nil, nil, err
    }
    handshake := &Handshake{
      localPublicKeyED: connection.localPublicKeyED,
      localPrivateKeyED: connection.localPrivateKeyED,
      peerPublicKeyED: packet.SourcePublicKeyED[:],
      privateKeyDH: privateKeyDH,
      publicKeyDH: privateKeyDH.PublicKey(),
    }
    return handshake, nil, nil
  }
  return nil, &Transaction[Packet]{Chunks: []Packet{packet}, Des: &Identifier{PublicKeyED: packet.TargetPublicKeyED[:]}}, nil
}

func (connection *Connection) onData(packet Packet, source *Identifier) (PacketsHandler, *Transaction[Packet], error) {
  data := packet.(*Data)
  connection.rwMutex.RLock()
  channel, ok := connection.streamIDToChannel[data.StreamID]
  connection.rwMutex.RUnlock()
  if ok {
    return channel.onData(data, source)
  }
  channel = NewChannel(connection, data.StreamID)
  connection.rwMutex.Lock()
  connection.streamIDToChannel[data.StreamID] = channel
  connection.rwMutex.Unlock()
  return channel.onData(data, source)
}

func (connection *Connection) PacketTransactionToBytesTransaction(packets *Transaction[Packet]) *Transaction[[]byte] {
  start := 0
  sendBuffers := make([][]byte, 1)
  chunks := packets.Chunks
  for start < len(chunks) {
    end, bufferLen := nextPacketIndex(chunks, start)
    buffer := make([]byte, bufferLen)
    n := 0
    for i := start; i < end; i++ {
      c, _ := chunks[i].Serialize(buffer[n:])
      n += c
    }
    connection.encrypt(buffer, buffer)
    sendBuffers = append(sendBuffers, buffer)
    start = end
  }
  return &Transaction[[]byte]{Des: packets.Des, Chunks: sendBuffers}
}

func (connection *Connection) closeChannel(id byte) {
  connection.rwMutex.Lock()
  defer connection.rwMutex.Unlock()
  delete(connection.streamIDToChannel, id)
  if len(connection.streamIDToChannel) == 0 {
    connection.router.mutex.Lock()
    defer connection.router.mutex.Unlock()
    delete(connection.router.ipToHandler, connection.addr.String())
  }
}

func segments(buffer []byte) [][]byte {
  start := 0
  segments := make([][]byte, 0)
  for start < len(buffer) {
    end := start + MaxPacketSize
    if end > len(buffer) {
      end = len(buffer)
    }
    segments = append(segments, buffer[start:end])
    start = end
  }
  return segments
}

