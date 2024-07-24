package gop2p

import "sync"

type stream struct {
  streamID byte
  sequenceNumber uint32
  ackedSequenceNumber uint32
  ackNumber uint32
  rxBuffer []*Data
  txPacketsMap map[uint32]*Data
  mutex sync.Mutex
  needAck bool
  needResend bool
}

func newStream(streamID byte) *stream {
  return &stream{
    streamID: streamID,
    sequenceNumber: 0,
    ackedSequenceNumber: 0,
    ackNumber: 0,
    rxBuffer: make([]*Data, 0),
    txPacketsMap: make(map[uint32]*Data),
    needAck: false,
  }
}

func (s *stream) close() Packet {
  s.mutex.Lock()
  defer s.mutex.Unlock()
  packet := &Data{
    StreamID: s.streamID,
    SequenceNumber: s.sequenceNumber,
    AckNumber: s.ackNumber,
    DataType: DataFinished,
  }
  s.txPacketsMap[s.sequenceNumber] = packet
  s.sequenceNumber += 1
  return packet
}

func (s *stream) onSend(data []byte) []Packet {
  segments := segments(data)
  packets := make([]Packet, len(segments))
  s.mutex.Lock()
  defer s.mutex.Unlock()
  for i, segment := range segments {
    packet := &Data{
      StreamID: s.streamID,
      Data: segment,
      SequenceNumber: s.sequenceNumber,
      DataType: 0,
    }
    s.txPacketsMap[s.sequenceNumber] = packet
    s.sequenceNumber += 1
    packets[i] = packet
  }
  if s.needAck {
    packets[0].(*Data).DataType |= DataAck
    s.needAck = false
    packets[0].(*Data).AckNumber = s.ackNumber
  }
  return packets
}

func (s *stream) ack() Packet {
  s.mutex.Lock()
  defer s.mutex.Unlock()
  packet := &Data{
    StreamID: s.streamID,
    SequenceNumber: s.sequenceNumber,
    DataType: DataAck,
    AckNumber: s.ackNumber,
    Data: make([]byte, 0),
  }
  s.needAck = false
  return packet
}

func (s *stream) tryAck() Packet {
  s.mutex.Lock()
  defer s.mutex.Unlock()
  if s.needAck {
    packet := &Data{
      StreamID: s.streamID,
      SequenceNumber: s.sequenceNumber,
      DataType: DataAck,
      AckNumber: s.ackNumber,
      Data: make([]byte, 0),
    }
    s.needAck = false
    return packet
  }
  return nil
}
func (s *stream) onData(data *Data, consumableBuffer []byte) (bool, []Packet, []byte) {
  needResend := false
  needAck := false
  s.mutex.Lock()
  if s.ackedSequenceNumber < data.AckNumber && data.DataType & DataAck != 0 {
    for k := s.ackedSequenceNumber; k < data.AckNumber; k += 1 {
      delete(s.txPacketsMap, k)
    }
    s.ackedSequenceNumber = data.AckNumber
    if s.sequenceNumber < s.ackedSequenceNumber {
      s.sequenceNumber = s.ackedSequenceNumber
    }
    needResend = true
  }
  if s.ackNumber <= data.SequenceNumber {
    s.rxBuffer = addDataToBuffer(s.rxBuffer, data)
    s.rxBuffer, consumableBuffer, s.ackNumber = updateRxBufferConsumableAckNumber(s.rxBuffer, consumableBuffer, s.ackNumber)
    needAck = true
  }
  closed := len(s.rxBuffer) > 0 && s.rxBuffer[0].DataType & DataFinished != 0
  if !needResend {
    s.needAck = s.needAck || needAck
    s.mutex.Unlock()
    return closed, nil, consumableBuffer
  }
  requestedPacket, ok := s.txPacketsMap[data.AckNumber]
  s.mutex.Unlock()
  if !ok {
    requestedPacket = &Data{
      StreamID: s.streamID,
      SequenceNumber: s.ackedSequenceNumber,
      AckNumber: s.ackNumber,
      DataType: 0,
      Data: make([]byte, 0),
    }
  }
  if needAck {
    requestedPacket.DataType |= DataAck
    s.mutex.Lock()
    requestedPacket.AckNumber = s.ackNumber
    s.mutex.Unlock()
  }
  return closed, []Packet{requestedPacket}, consumableBuffer
}

func addDataToBuffer(buffer []*Data, transaction *Data) []*Data {
  k := 0
  for ; k < len(buffer) && buffer[k].SequenceNumber < transaction.SequenceNumber; k += 1 {}
  if k == len(buffer) {
    buffer = append(buffer, transaction)
  } else if buffer[k].SequenceNumber == transaction.SequenceNumber {
    buffer[k] = transaction
  } else {
    buffer = append(buffer, nil)
    copy(buffer[k + 1:], buffer[k:])
    buffer[k] = transaction
  }
  return buffer
}

func updateRxBufferConsumableAckNumber(buffer []*Data, consumableBuffer []byte, ackNumber uint32) ([]*Data, []byte, uint32) {
  if consumableBuffer == nil {
    consumableBuffer = make([]byte, 0, MaxDataSize)
  }
  k := 0
  for ; k < len(buffer) && buffer[k].SequenceNumber == ackNumber && buffer[k].DataType & DataFinished == 0; k += 1 {
    consumableBuffer = append(consumableBuffer, buffer[k].Data...)
    if len(buffer[k].Data) != 0 {
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
