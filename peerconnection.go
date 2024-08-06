package gop2p

import (
	"crypto/aes"
	"net"
	"sync"
)

type peerConnection struct {
  addr *net.UDPAddr
  peerPublicKeyED []byte
  secretAES []byte
  streams map[byte]*stream
  txStream *mergeStream[packet]
  rwMutex sync.RWMutex
  incomingStream chan byte
}

func newPeerConnection(addr *net.UDPAddr, peerPublicKeyED []byte, secretAES []byte, maxStreamQueue int) *peerConnection {
  return &peerConnection{
    addr: addr,
    peerPublicKeyED: peerPublicKeyED,
    secretAES: secretAES,
    streams: make(map[byte]*stream),
    txStream: newMergeStream[packet](),
    incomingStream: make(chan byte, maxStreamQueue),
  }
}

func (connection *peerConnection) destruct() {
  connection.rwMutex.Lock()
  defer connection.rwMutex.Unlock()
  if connection.incomingStream == nil {
    return
  }
  close(connection.incomingStream)
  connection.incomingStream = nil
}

func (connection *peerConnection) encrypt(des []byte, plain []byte) error {
  block, err := aes.NewCipher(connection.secretAES)
  if err != nil {
    return err
  }
  for k := 0; k < len(plain); k += aes.BlockSize {
    block.Encrypt(des[k:], plain[k:])
  }
  return nil
}

func (connection *peerConnection) decrypt(des []byte, cipher []byte) error {
  block, err := aes.NewCipher(connection.secretAES)
  if err != nil {
    return err
  }
  for k := 0; k < len(cipher); k += aes.BlockSize {
    block.Decrypt(des[k:], cipher[k:])
  }
  return nil
}

func (connection *peerConnection) consume(buf []byte, streamID byte, udpConn *net.UDPConn) (int, bool, error) {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return -1, false, newStreamNotEstablishedError(streamID)
  }
  n, consumed, p := stream.consume(buf)
  if p != nil {
    err := connection.sendPackets([]packet{p}, udpConn)
    return n, consumed, err
  }
  return n, consumed, nil
}

func (connection *peerConnection) ack(streamID byte, udpConn *net.UDPConn) error {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return newStreamNotEstablishedError(streamID)
  }
  p := stream.ack()
  return connection.sendPackets([]packet{p}, udpConn)
}

func (connection *peerConnection) tryAck(streamID byte, udpConn *net.UDPConn) error {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return newStreamNotEstablishedError(streamID)
  }
  p := stream.tryAck()
  if p == nil {
    return nil
  }
  return connection.sendPackets([]packet{p}, udpConn)
}

func (connection *peerConnection) closeStream(streamID byte) packet {
  connection.rwMutex.Lock()
  defer connection.rwMutex.Unlock()
  stream, ok := connection.streams[streamID]
  if !ok {
    return nil
  }
  delete(connection.streams, streamID)
  return stream.close()
}

func (connection *peerConnection) close(udpConn *net.UDPConn) error {
  connection.destruct()
  p := &connectionClosed{}
  return connection.sendPackets([]packet{p}, udpConn)
}

func (connection *peerConnection) onSend(buf []byte, streamID byte, udpConn *net.UDPConn) (int, error) {
  connection.rwMutex.RLock()
  stream, ok := connection.streams[streamID]
  connection.rwMutex.RUnlock()
  if !ok {
    return 0, newStreamNotEstablishedError(streamID)
  }
  packets, l := stream.onSend(buf)
  err := connection.sendPackets(packets, udpConn)
  return l, err
}

func (connection *peerConnection) onData(d *data, udpConn *net.UDPConn) error {
  connection.rwMutex.Lock()
  stream, ok := connection.streams[d.streamID]
  if !ok {
    if d.dataType & DataNewStream == 0 {
      streamClosed := &data{
	streamID: d.streamID,
	dataType: DataClosed,
      }
      connection.rwMutex.Unlock()
      return connection.sendPackets([]packet{streamClosed}, udpConn)
    }
    stream = newStream(d.streamID)
    connection.streams[d.streamID] = stream
    connection.incomingStream <- d.streamID
  }
  connection.rwMutex.Unlock()
  closed, packets := stream.onData(d)
  if closed {
    connection.rwMutex.Lock()
    delete(connection.streams, d.streamID)

    connection.rwMutex.Unlock()
  }
  if packets == nil {
    return nil
  }
  return connection.sendPackets(packets, udpConn)
}

func (conn *peerConnection) sendPackets(packets []packet, udpConn *net.UDPConn) error {
  packets = conn.txStream.add(packets)
  if packets == nil {
    return nil
  }
  bytesToSend := serializePackets(packets)
  for _, b := range bytesToSend {
    err := conn.encrypt(b, b)
    if err != nil {
      return err
    }
    _, err = udpConn.WriteToUDP(b, conn.addr)
    if err != nil {
      return err
    }
  }
  return nil
}
