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
  incomingDataFromNewStream chan *data
}

func newEncryptedConnection(addr *net.UDPAddr, peerPublicKeyED []byte, secretAES []byte) *encryptedConnection {
  return &encryptedConnection{
    addr: addr,
    peerPublicKeyED: peerPublicKeyED,
    secretAES: secretAES,
    streams: make(map[byte]*stream),
    txStream: newMergeStream[packet](),
    incomingDataFromNewStream: make(chan *data, 1),
  }
}

func (connection *encryptedConnection) destruct() {
  close(connection.incomingDataFromNewStream)
  connection.rwMutex.Lock()
  for _, stream := range connection.streams {
    stream.destruct()
  }
  connection.rwMutex.Unlock()
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

func (connection *encryptedConnection) consume(buf []byte, streamID byte, udpConn *net.UDPConn, needAck bool) (int, bool, error) {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return -1, false, newStreamNotFoundError(streamID)
  }
  n, consumed, p := stream.consume(buf, needAck)
  if p != nil {
    packets := connection.txStream.add([]packet{p})
    if packets == nil {
      return n, consumed, nil
    }
    bytesToSend := serializePackets(packets)
    for _, b := range bytesToSend {
      connection.encrypt(b, b)
      _, err := udpConn.WriteToUDP(b, connection.addr)
      if err != nil {
	return n, consumed, err
      }
    }
  }
  return n, consumed, nil
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

func (connection *encryptedConnection) closeStream(udpConn *net.UDPConn, streamID byte) error {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return nil
  }
  var err error = nil
  p := stream.close()
  packets := connection.txStream.add([]packet{p})
  if packets != nil {
    bytesToSend := serializePackets(packets)
    for _, b := range bytesToSend {
      connection.encrypt(b, b)
      _, err = udpConn.WriteToUDP(b, connection.addr)
      if err != nil {
	break
      }
    }
  }
  connection.rwMutex.Lock()
  delete(connection.streams, streamID)
  connection.rwMutex.Unlock()
  return err
}

func (connection *encryptedConnection) close(udpConn *net.UDPConn) error {
  defer connection.destruct()
  packets := make([]packet, 0)
  connection.rwMutex.Lock()
  for _, stream := range connection.streams {
    packet := stream.close()
    packets = append(packets, packet)
  }
  connection.streams = make(map[byte]*stream)
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

func (connection *encryptedConnection) onDataFromNewStream(incoming *data, udpConn *net.UDPConn) (bool, error) {
  connection.rwMutex.Lock()
  _, ok := connection.streams[incoming.streamID]
  if !ok {
    connection.streams[incoming.streamID] = newStream(incoming.streamID)
  }
  connection.rwMutex.Unlock()
  return connection.onData(incoming, udpConn)
}

func (connection *encryptedConnection) onSend(data []byte, streamID byte, udpConn *net.UDPConn) error {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return newStreamNotFoundError(streamID)
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

func (connection *encryptedConnection) onData(d *data, udpConn *net.UDPConn) (bool, error) {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[d.streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    connection.incomingDataFromNewStream <- d
    return false, nil
  }
  connectionClosed := false
  closed, packets := stream.onData(d)
  if closed {
    connection.rwMutex.Lock()
    delete(connection.streams, d.streamID)
    if len(connection.streams) == 0 {
      connectionClosed = true
    }
    connection.rwMutex.Unlock()
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
