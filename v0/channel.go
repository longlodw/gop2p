package v0

import "sync"

type Channel struct {
  streamID byte
  sequenceNumber uint32
  ackedSequenceNumber uint32
  ackNumber uint32
  rxBuffer []*Data
  txPacketsMap map[uint32]*Data
  rxConsumable []byte
  connection *Connection
  mutex *sync.Mutex
  needAck bool
  needResend bool
}

func NewChannel(connection *Connection, streamID byte) *Channel {
  return &Channel{
    streamID: streamID,
    sequenceNumber: 0,
    ackedSequenceNumber: 0,
    ackNumber: 0,
    rxBuffer: make([]*Data, 0),
    txPacketsMap: make(map[uint32]*Data),
    rxConsumable: nil,
    connection: connection,
    mutex: &sync.Mutex{},
    needAck: false,
    needResend: false,
  }
}

func (channel *Channel) ConsumeRx(buf []byte) int {
  channel.mutex.Lock()
  defer channel.mutex.Unlock()
  if channel.rxConsumable == nil {
    return -1
  }
  n := copy(buf, channel.rxConsumable)
  if n < len(channel.rxConsumable) {
    channel.rxConsumable = channel.rxConsumable[n:]
  } else {
    channel.rxConsumable = nil
  }
  return n
}

func (channel *Channel) onData(data *Data, source *Identifier) (PacketsHandler, *Transaction[Packet], error) {
  channel.mutex.Lock()
  defer channel.mutex.Unlock()
  if channel.ackedSequenceNumber < data.AckNumber && data.DataType & DataAck != 0 {
    for k := channel.ackedSequenceNumber; k < data.AckNumber; k += 1 {
      delete(channel.txPacketsMap, k)
    }
    channel.ackedSequenceNumber = data.AckNumber
    if channel.sequenceNumber < channel.ackedSequenceNumber {
      channel.sequenceNumber = channel.ackedSequenceNumber
    }
    channel.needResend = true
  }
  if channel.ackNumber <= data.SequenceNumber {
    channel.rxBuffer = addDataToBuffer(channel.rxBuffer, data)
    channel.rxBuffer, channel.rxConsumable, channel.ackNumber = updateRxBufferConsumableAckNumber(channel.rxBuffer, channel.rxConsumable, channel.ackNumber)
    channel.needAck = true
  }

  if len(channel.rxBuffer) > 0 && channel.rxBuffer[0].SequenceNumber == channel.ackNumber && channel.rxBuffer[0].DataType & DataFinished != 0 {
    defer func () {
      channel.connection.rwMutex.Lock()
      defer channel.connection.rwMutex.Unlock()
      delete(channel.connection.streamIDToChannel, channel.streamID)
    }()
    channel.rxBuffer = channel.rxBuffer[:0]
    finish := &Data{
      StreamID: channel.streamID,
      SequenceNumber: channel.ackedSequenceNumber,
      AckNumber: channel.ackNumber,
      DataType: DataFinished | DataAck,
      Data: make([]byte, 0),
    }
    packets := channel.connection.txStream.Add([]Packet{finish})
    if packets == nil {
      return nil, nil, nil
    }
    transaction := &Transaction[Packet]{
      Des: source,
      Chunks: packets,
    }
    return nil, transaction, nil
  }
  if !channel.needResend {
    return nil, nil, nil
  }
  channel.needResend = false
  requestedPacket, ok := channel.txPacketsMap[channel.ackedSequenceNumber]
  if !ok {
    requestedPacket = &Data{
      StreamID: channel.streamID,
      SequenceNumber: channel.ackedSequenceNumber,
      AckNumber: channel.ackNumber,
      DataType: 0,
      Data: make([]byte, 0),
    }
  }
  packets := channel.connection.txStream.Add([]Packet{requestedPacket})
  if packets == nil {
    return nil, nil, nil
  }
  packetsConverted := make([]Packet, len(packets))
  for i, packet := range packets {
    packetsConverted[i] = packet
  }
  transaction := &Transaction[Packet]{
    Des: source,
    Chunks: packetsConverted,
  }
  return nil, transaction, nil
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
    consumableBuffer = make([]byte, 0, 1024)
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
