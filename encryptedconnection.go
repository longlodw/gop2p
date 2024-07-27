package gop2p

import (
	"crypto/aes"
	"net"
	"sync"
)

type encryptedConnection struct {
  addr *net.UDPAddr
  peerPublicKeyED []byte
  secretAES []byte
  streams map[byte]*stream
  txStream *mergeStream[packet]
  rwMutex sync.RWMutex
  consumableBuffer chan consumable
}

type consumable struct {
  buffer []byte
  streamID byte
}

func newEncryptedConnection(addr *net.UDPAddr, peerPublicKeyED []byte, secretAES []byte) *encryptedConnection {
  return &encryptedConnection{
    addr: addr,
    peerPublicKeyED: peerPublicKeyED,
    secretAES: secretAES,
    streams: make(map[byte]*stream),
    txStream: newMergeStream[packet](),
    consumableBuffer: make(chan consumable, 8),
  }
}

func (connection *encryptedConnection) encrypt(des []byte, plain []byte) error {
  block, err := aes.NewCipher(connection.secretAES)
  if err != nil {
    return err
  }
  for k := 0; k < len(plain); k += aes.BlockSize {
    block.Encrypt(des[k:], plain[k:])
  }
  return nil
}

func (connection *encryptedConnection) decrypt(des []byte, cipher []byte) error {
  block, err := aes.NewCipher(connection.secretAES)
  if err != nil {
    return err
  }
  for k := 0; k < len(cipher); k += aes.BlockSize {
    block.Decrypt(des[k:], cipher[k:])
  }
  return nil
}

func (connection *encryptedConnection) ack(streamID byte, udpConn *net.UDPConn) error {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return newStreamNotFoundError(streamID)
  }
  p := stream.ack()
  packets := connection.txStream.add([]packet{p})
  if packets == nil {
    return nil
  }
  bytesToSend := serializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return err
    }
  }
  return nil
}

func (connection *encryptedConnection) tryAck(streamID byte, udpConn *net.UDPConn) error {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return newStreamNotFoundError(streamID)
  }
  p := stream.tryAck()
  if p == nil {
    return nil
  }
  packets := connection.txStream.add([]packet{p})
  if packets == nil {
    return nil
  }
  bytesToSend := serializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return err
    }
  }
  return nil
}

func (connection *encryptedConnection) closeStream(udpConn *net.UDPConn, streamID byte) (bool, error) {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return false, nil
  }

  closed := false
  connection.rwMutex.Lock()
  delete(connection.streams, streamID)
  if len(connection.streams) == 0 {
    closed = true
  }
  connection.rwMutex.Unlock()

  p := stream.close()
  packets := connection.txStream.add([]packet{p})
  if packets == nil {
    return closed, nil
  }
  bytesToSend := serializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return closed, err
    }
  }
  return closed, nil
}

func (connection *encryptedConnection) close(udpConn *net.UDPConn) error {
  packets := make([]packet, 0)
  connection.rwMutex.Lock()
  for _, stream := range connection.streams {
    packet := stream.close()
    packets = append(packets, packet)
  }
  connection.rwMutex.Unlock()
  packets = connection.txStream.add(packets)
  if packets == nil {
    return nil
  }
  bytesToSend := serializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return err
    }
  }
  return nil
}

func (connection *encryptedConnection) onSend(data []byte, streamID byte, udpConn *net.UDPConn) error {
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
  bytesToSend := serializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return err
    }
  }
  return nil
}

func (connection *encryptedConnection) onData(data *data, udpConn *net.UDPConn) (bool, error) {
  connectionClosed := false
  connection.rwMutex.RLock()
  stream, ok := connection.streams[data.streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    stream = newStream(data.streamID)
    connection.rwMutex.Lock()

    connection.streams[data.streamID] = stream
    connection.rwMutex.Unlock()
  }
  closed, packets, consumableBuffer := stream.onData(data, nil)
  if closed {
    connection.rwMutex.Lock()
    delete(connection.streams, data.streamID)
    if len(connection.streams) == 0 {
      connectionClosed = true
    }
    connection.rwMutex.Unlock()
  }
  if consumableBuffer != nil {
    connection.consumableBuffer <- consumable{consumableBuffer, data.streamID}
  }
  if packets == nil {
    return connectionClosed, nil
  }
  packets = connection.txStream.add(packets)
  if packets == nil {
    return connectionClosed, nil
  }
  bytesToSend := serializePackets(packets)
  for _, b := range bytesToSend {
    connection.encrypt(b, b)
    _, err := udpConn.WriteToUDP(b, connection.addr)
    if err != nil {
      return connectionClosed, err
    }
  }
  return connectionClosed, nil
}
