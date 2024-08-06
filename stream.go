package gop2p

import (
	"sync"
)

type stream struct {
  streamID byte
  sequenceNumber uint32
  ackedSequenceNumber uint32
  ackNumber uint32
  rxBuffer []*data
  txPacketsMap map[uint32]*data
  mutex sync.Mutex
  needAck bool
  consumableBuffer [][]byte
}

func newStream(streamID byte) *stream {
  return &stream{
    streamID: streamID,
    sequenceNumber: 0,
    ackedSequenceNumber: 0,
    ackNumber: 0,
    rxBuffer: make([]*data, 0),
    txPacketsMap: make(map[uint32]*data),
    needAck: false,
    consumableBuffer: make([][]byte, 0),
  }
}

func (s *stream) close() packet {
  s.mutex.Lock()
  defer s.mutex.Unlock()
  packet := &data{
    streamID: s.streamID,
    dataType: DataClosed,
  }
  return packet
}

func (s *stream) onSend(buf []byte) ([]packet, int) {
  segments := segments(buf)
  packets := make([]packet, len(segments))
  var diff int64 = 0
  s.mutex.Lock()
  defer s.mutex.Unlock()
  if s.sequenceNumber < s.ackedSequenceNumber {
    diff = int64(s.ackedSequenceNumber - s.sequenceNumber - 1)
  } else {
    diff = int64(^uint32(0) - (s.sequenceNumber - s.ackedSequenceNumber))
  }
  if diff <= int64(len(segments)) {
    segments = segments[:diff]
  }
  var dataType byte = 0
  if s.ackedSequenceNumber & s.ackNumber == 0 {
    dataType |= DataNewStream
  }
  l := 0
  for i, segment := range segments {
    packet := &data{
      streamID: s.streamID,
      data: segment,
      sequenceNumber: s.sequenceNumber,
      dataType: dataType,
    }
    s.txPacketsMap[s.sequenceNumber] = packet
    s.sequenceNumber += 1
    packets[i] = packet
    l += len(segment)
  }
  if s.needAck {
    packets[0].(*data).dataType |= DataAck
    s.needAck = false
    packets[0].(*data).ackNumber = s.ackNumber
  }
  return packets, l
}

func (s *stream) consume(buf []byte) (int, bool, packet) {
  s.mutex.Lock()
  defer s.mutex.Unlock()
  n := 0
  idx := 0
  for _, segment := range s.consumableBuffer {
    l := copy(buf[n:], segment)
    n += l
    if l != len(segment) {
      s.consumableBuffer[idx] = segment[l:]
      break
    }
    idx++
  }
  var p packet = nil
  if idx == len(s.consumableBuffer) {
    s.consumableBuffer = s.consumableBuffer[:0]
    if n > 0 {
      p = &data{
        streamID: s.streamID,
        sequenceNumber: s.sequenceNumber,
        dataType: DataAck,
        ackNumber: s.ackNumber,
        data: make([]byte, 0),
      }
      s.needAck = false
    }
  } else {
    s.consumableBuffer = s.consumableBuffer[idx:]
  }
  return n, idx > 0 || n > 0, p
}

func (s *stream) ack() packet {
  s.mutex.Lock()
  defer s.mutex.Unlock()
  packet := &data{
    streamID: s.streamID,
    sequenceNumber: s.sequenceNumber,
    dataType: DataAck,
    ackNumber: s.ackNumber,
    data: make([]byte, 0),
  }
  s.needAck = false
  return packet
}

func (s *stream) tryAck() packet {
  s.mutex.Lock()
  defer s.mutex.Unlock()
  if s.needAck {
    packet := &data{
      streamID: s.streamID,
      sequenceNumber: s.sequenceNumber,
      dataType: DataAck,
      ackNumber: s.ackNumber,
      data: make([]byte, 0),
    }
    s.needAck = false
    return packet
  }
  return nil
}

func (s *stream) updateSequenceNumber(dataAckNumber uint32) {
  s.mutex.Lock()
  defer s.mutex.Unlock()
  k := s.ackNumber
  for ; k != dataAckNumber && k != s.sequenceNumber; k += 1 {
    delete(s.txPacketsMap, k)
  }
  s.ackedSequenceNumber = k
  if s.sequenceNumber == s.ackedSequenceNumber && dataAckNumber > s.ackedSequenceNumber {
    s.sequenceNumber = dataAckNumber
    s.ackedSequenceNumber = dataAckNumber
  }
}

func (s *stream) onData(dataPtr *data) (bool, []packet) {
  needResend := false
  needAck := false
  if dataPtr.dataType & DataClosed != 0 {
    return true, nil
  }
  if dataPtr.dataType & DataAck != 0 {
    s.updateSequenceNumber(dataPtr.ackNumber)
    needResend = true
  }
  s.mutex.Lock()
  if s.ackNumber <= dataPtr.sequenceNumber {
    s.rxBuffer = addDataToBuffer(s.rxBuffer, dataPtr)
    s.rxBuffer, s.consumableBuffer, s.ackNumber = updateRxBufferConsumableAckNumber(s.rxBuffer, s.consumableBuffer, s.ackNumber)
    if len(dataPtr.data) != 0 {
      needAck = true
    }
  }
  if !needResend {
    s.needAck = s.needAck || needAck
    s.mutex.Unlock()
    return false, nil
  }
  requestedPacket, ok := s.txPacketsMap[dataPtr.ackNumber]
  s.mutex.Unlock()
  if !ok {
    requestedPacket = &data{
      streamID: s.streamID,
      sequenceNumber: s.ackedSequenceNumber,
      ackNumber: s.ackNumber,
      dataType: 0,
      data: make([]byte, 0),
    }
  }
  if needAck {
    requestedPacket.dataType |= DataAck
    s.mutex.Lock()
    requestedPacket.ackNumber = s.ackNumber
    s.mutex.Unlock()
  }
  return false, []packet{requestedPacket}
}

func addDataToBuffer(buffer []*data, transaction *data) []*data {
  k := 0
  for ; k < len(buffer) && buffer[k].sequenceNumber < transaction.sequenceNumber; k += 1 {}
  if k == len(buffer) {
    buffer = append(buffer, transaction)
  } else if buffer[k].sequenceNumber == transaction.sequenceNumber {
    buffer[k] = transaction
  } else {
    buffer = append(buffer, nil)
    copy(buffer[k + 1:], buffer[k:])
    buffer[k] = transaction
  }
  return buffer
}

func updateRxBufferConsumableAckNumber(buffer []*data, consumableBuffer [][]byte, ackNumber uint32) ([]*data, [][]byte, uint32) {
  k := 0
  for ; k < len(buffer) && buffer[k].sequenceNumber == ackNumber; k += 1 {
    consumableBuffer = append(consumableBuffer, buffer[k].data)
    if len(buffer[k].data) != 0 {
      ackNumber += 1
    }
  }
  if k == len(buffer) {
    buffer = buffer[:0]
  } else {
    buffer = buffer[k:]
  }
  return buffer, consumableBuffer, ackNumber
}

func segments(buffer []byte) [][]byte {
  start := 0
  segments := make([][]byte, 0)
  for start < len(buffer) {
    end := start + MaxDataSize
    if end > len(buffer) {
      end = len(buffer)
    }
    segments = append(segments, buffer[start:end])
    start = end
  }
  return segments
}
