package v0

import (
  "net"
  "sync"
  "crypto/aes"
  "errors"
)

type EncryptedConnection struct {
  addr *net.UDPAddr
  peerPublicKeyED []byte
  secretAES []byte
  streams map[byte]*stream
  txStream *MergeStream[Packet]
  rwMutex sync.RWMutex
}

func NewEncryptedConnection(addr *net.UDPAddr, peerPublicKeyED []byte, secretAES []byte) *EncryptedConnection {
  return &EncryptedConnection{
    addr: addr,
    peerPublicKeyED: peerPublicKeyED,
    secretAES: secretAES,
    streams: make(map[byte]*stream),
    txStream: NewMergeStream[Packet](),
  }
}

func (connection *EncryptedConnection) encrypt(des []byte, plain []byte) error {
  block, err := aes.NewCipher(connection.secretAES)
  if err != nil {
    return err
  }
  block.Encrypt(des, plain)
  return nil
}

func (connection *EncryptedConnection) decrypt(des []byte, cipher []byte) error {
  block, err := aes.NewCipher(connection.secretAES)
  if err != nil {
    return err
  }
  block.Decrypt(des, cipher)
  return nil
}

func (connection *EncryptedConnection) ack(streamID byte, udpConn *net.UDPConn) error {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return errors.New("Stream not found")
  }
  packet := stream.ack()
  packets := connection.txStream.Add([]Packet{packet})
  if packets == nil {
    return nil
  }
  bytesToSend := SerializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return err
    }
  }
  return nil
}

func (connection *EncryptedConnection) tryAck(streamID byte, udpConn *net.UDPConn) error {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return errors.New("Stream not found")
  }
  packet := stream.tryAck()
  if packet == nil {
    return nil
  }
  packets := connection.txStream.Add([]Packet{packet})
  if packets == nil {
    return nil
  }
  bytesToSend := SerializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return err
    }
  }
  return nil
}

func (connection *EncryptedConnection) onSend(data []byte, streamID byte, udpConn *net.UDPConn) error {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    stream = newStream(streamID)
    connection.rwMutex.Lock()
    connection.streams[streamID] = stream
    connection.rwMutex.Unlock()
  }
  packets := stream.onSend(data)
  if packets == nil {
    return nil
  }
  bytesToSend := SerializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return err
    }
  }
  return nil
}

func (connection *EncryptedConnection) onData(data *Data, consumableBuffer []byte, udpConn *net.UDPConn) (bool, []byte, error) {
  connectionClosed := false
  connection.rwMutex.RLock()
  stream, ok := connection.streams[data.StreamID]
  connection.rwMutex.RUnlock()
  if !ok {
    stream = newStream(data.StreamID)
    connection.rwMutex.Lock()

    connection.streams[data.StreamID] = stream
    connection.rwMutex.Unlock()
  }
  closed, packets, consumableBuffer := stream.onData(data, consumableBuffer)
  if closed {
    connection.rwMutex.Lock()
    delete(connection.streams, data.StreamID)
    if len(connection.streams) == 0 {
      connectionClosed = true
    }
    connection.rwMutex.Unlock()
  }
  if packets == nil {
    return connectionClosed, consumableBuffer, nil
  }
  packets = connection.txStream.Add(packets)
  if packets == nil {
    return connectionClosed, consumableBuffer, nil
  }
  bytesToSend := SerializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return connectionClosed, consumableBuffer, err
    }
  }
  return connectionClosed, consumableBuffer, nil
}
