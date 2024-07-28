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
  hasNewData bool
  consumableBuffer [][]byte
  incomingData chan *data
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
    hasNewData: false,
    consumableBuffer: make([][]byte, 0),
    incomingData: make(chan *data, 16),
  }
}

func (s *stream) destruct() {
  close(s.incomingData)
}

func (s *stream) close() packet {
  defer s.destruct()
  s.mutex.Lock()
  defer s.mutex.Unlock()
  packet := &data{
    streamID: s.streamID,
    sequenceNumber: s.sequenceNumber,
    ackNumber: s.ackNumber,
    dataType: DataFinished,
  }
  s.txPacketsMap[s.sequenceNumber] = packet
  s.sequenceNumber += 1
  return packet
}

func (s *stream) onSend(buf []byte) []packet {
  segments := segments(buf)
  packets := make([]packet, len(segments))
  s.mutex.Lock()
  defer s.mutex.Unlock()
  for i, segment := range segments {
    packet := &data{
      streamID: s.streamID,
      data: segment,
      sequenceNumber: s.sequenceNumber,
      dataType: 0,
    }
    s.txPacketsMap[s.sequenceNumber] = packet
    s.sequenceNumber += 1
    packets[i] = packet
  }
  if s.needAck {
    packets[0].(*data).dataType |= DataAck
    s.needAck = false
    packets[0].(*data).ackNumber = s.ackNumber
  }
  return packets
}

func (s *stream) consume(buf []byte, needAck bool) (int, bool, packet) {
  s.mutex.Lock()
  defer s.mutex.Unlock()
  if !s.hasNewData && len(s.consumableBuffer) == 0 {
    var p packet = nil
    if needAck {
      p = &data{
        streamID: s.streamID,
        sequenceNumber: s.sequenceNumber,
        dataType: DataAck,
        ackNumber: s.ackNumber,
        data: make([]byte, 0),
      }
      s.needAck = false
    }
    return -1, false, p
  }
  s.hasNewData = false
  n := 0
  idx := 0
  for _, segment := range s.consumableBuffer {
    l := copy(buf[n:], segment)
    n += l
    if l != len(segment) {
      break
    }
    idx++
  }
  var p packet = nil
  if idx == len(s.consumableBuffer) {
    s.consumableBuffer = s.consumableBuffer[:0]
    p = &data{
      streamID: s.streamID,
      sequenceNumber: s.sequenceNumber,
      dataType: DataAck,
      ackNumber: s.ackNumber,
      data: make([]byte, 0),
    }
    s.needAck = false
  } else {
    s.consumableBuffer = s.consumableBuffer[idx:]
  }
  return n, true, p
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

func (s *stream) onData(dataPtr *data) (bool, []packet) {
  needResend := false
  needAck := false
  s.mutex.Lock()
  if s.ackedSequenceNumber < dataPtr.ackNumber && dataPtr.dataType & DataAck != 0 {
    for k := s.ackedSequenceNumber; k < dataPtr.ackNumber; k += 1 {
      delete(s.txPacketsMap, k)
    }
    s.ackedSequenceNumber = dataPtr.ackNumber
    if s.sequenceNumber < s.ackedSequenceNumber {
      s.sequenceNumber = s.ackedSequenceNumber
    }
    needResend = true
  }
  if s.ackNumber <= dataPtr.sequenceNumber {
    s.rxBuffer = addDataToBuffer(s.rxBuffer, dataPtr)
    s.rxBuffer, s.consumableBuffer, s.ackNumber, s.hasNewData = updateRxBufferConsumableAckNumber(s.rxBuffer, s.consumableBuffer, s.ackNumber, s.hasNewData)
    needAck = true
  }
  closed := len(s.rxBuffer) > 0 && s.rxBuffer[0].dataType & DataFinished != 0
  defer func() {
    if closed {
      s.destruct()
    }
  }()
  if !needResend {
    s.needAck = s.needAck || needAck
    s.mutex.Unlock()
    return closed, nil
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
  return closed, []packet{requestedPacket}
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

func updateRxBufferConsumableAckNumber(buffer []*data, consumableBuffer [][]byte, ackNumber uint32, oldHasNewData bool) ([]*data, [][]byte, uint32, bool) {
  hasNewData := false
  k := 0
  for ; k < len(buffer) && buffer[k].sequenceNumber == ackNumber && buffer[k].dataType & DataFinished == 0; k += 1 {
    consumableBuffer = append(consumableBuffer, buffer[k].data)
    if len(buffer[k].data) != 0 {
      ackNumber += 1
    }
    hasNewData = true
  }
  if k == len(buffer) {
    buffer = buffer[:0]
  } else {
    buffer = buffer[k:]
  }
  return buffer, consumableBuffer, ackNumber, hasNewData || oldHasNewData
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
