package v0

import (
	"encoding/binary"
	"errors"
	"net"
)

type Hello struct {
  PublicKeyDH [PublicKeyDHSize]byte
  PublicKeyED [PublicKeyEDSize]byte
  Signature [SignatureSize]byte
  Cookie [CookieSize]byte
}

type HelloRetry struct {
  Cookie [CookieSize]byte
}

type Introduction struct {
  PublicKeyDH [PublicKeyDHSize]byte
  SourcePublicKeyED [PublicKeyEDSize]byte
  SourceIP [IPV6Size]byte
  SourcePort uint16
  TargetPublicKeyED [PublicKeyEDSize]byte
  Signature [SignatureSize]byte
}

type Data struct {
  StreamID byte
  DataType byte
  SequenceNumber uint32
  AckNumber uint32
  Data []byte
}

const (
  Version = 0
  MaxPacketSize = 1198
)

const (
  PacketHello byte = iota
  PacketHelloRetry
  PacketIntroduction
  PacketData
)

const (
  DataAck byte = 1
  DataFinished byte = 2
)

const (
  PublicKeyDHSize = 32
  PublicKeyEDSize = 32
  SignatureSize = 64
  CookieSize = 32
  IPV6Size = 16
  PortSize = 2
)

const (
  DataIDSize = 1
  DataTypeSize = 1
  DataSequenceNumberSize = 4
  DataAckNumberSize = 4
  DataHeaderSize = DataIDSize + DataTypeSize + DataSequenceNumberSize + DataAckNumberSize
  DataLengthSize = 2
  MaxDataSize = MaxPacketSize - HeaderSize - DataHeaderSize - DataLengthSize
)

const (
  VersionSize = 1
  PacketTypeSize = 1
  HeaderSize = VersionSize + PacketTypeSize
  HelloSize = PublicKeyDHSize + PublicKeyEDSize + SignatureSize + CookieSize
  IntroductionSize = PublicKeyDHSize + PublicKeyEDSize + IPV6Size + PortSize + PublicKeyEDSize + SignatureSize
)

type Packet interface {
  Type() byte
  Serialize([]byte) (int, error)
  BufferSize() int
}

type PacketsHandler interface {
  OnPacket(Packet, *Identifier) (PacketsHandler, *Transaction[Packet], error)
  Serialize(*Transaction[Packet]) *Transaction[[]byte]
  Deserialize([]byte) *Transaction[Packet]
}

func HandleBytes(packetsHandler PacketsHandler, buf []byte, addr *net.UDPAddr, newConnections chan *Connection) (PacketsHandler, *Transaction[[]byte], error) {
  transactions := packetsHandler.Deserialize(buf)
  if transactions == nil {
    return nil, nil, errors.New("Invalid bytes")
  }
  chunks := make([]Packet, 0)
  var ph PacketsHandler = nil
  for _, p := range transactions.Chunks {
    ph, tr, err := packetsHandler.OnPacket(p, transactions.Des)
    if err != nil {
      continue
    }
    if tr != nil {
      chunks = append(chunks, tr.Chunks...)
    }
    if ph != nil {
      break
    }
  }
  transactions.Chunks = chunks
  transactionsBytes := packetsHandler.Serialize(transactions)
  if _, ok := ph.(*Connection); ok {
    newConnections <- ph.(*Connection)
  }
  return ph, transactionsBytes, nil
}

func DefaultPacketSerialize(packets *Transaction[Packet]) *Transaction[[]byte] {
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
    sendBuffers = append(sendBuffers, buffer)
    start = end
  }
  return &Transaction[[]byte]{Des: packets.Des, Chunks: sendBuffers}
}

func nextPacketIndex(packets []Packet, start int) (int, int) {
  bufferLen := 0
  for i := start; i < len(packets); i++ {
    if packets[i].BufferSize() + bufferLen > MaxPacketSize {
      return i, bufferLen
    }
    bufferLen += packets[i].BufferSize()
  }
  return len(packets), bufferLen
}

func DeserializePacket(buffer []byte) (Packet, int, error) {
  if len(buffer) < 2 {
    return nil, -1, errors.New("Buffer too small")
  }

  if buffer[0] != Version {
    return nil, -1, errors.New("Invalid version")
  }

  packetType := buffer[1]
  buffer = buffer[2:]

  switch packetType {
  case PacketHello:
    return DeserializeHello(buffer)
  case PacketHelloRetry:
    return DeserializeHelloRetry(buffer)
  case PacketIntroduction:
    return DeserializeIntroduction(buffer)
  case PacketData:
    return DeserializeData(buffer)
  default:
    return nil, -1, errors.New("Invalid packet type")
  }
}

func DeserializeHello(buffer []byte) (*Hello, int, error) {
  if len(buffer) < HelloSize {
    return nil, -1, errors.New("Buffer too small")
  }

  hello := &Hello{}
  copy(hello.PublicKeyDH[:], buffer[:PublicKeyDHSize])
  buffer = buffer[PublicKeyDHSize:]
  copy(hello.PublicKeyED[:], buffer[:PublicKeyEDSize])
  buffer = buffer[PublicKeyEDSize:]
  copy(hello.Signature[:], buffer[:SignatureSize])
  buffer = buffer[SignatureSize:]
  copy(hello.Cookie[:], buffer[:CookieSize])

  return hello, HelloSize, nil
}

func DeserializeHelloRetry(buffer []byte) (*HelloRetry, int, error) {
  if len(buffer) < CookieSize {
    return nil, -1, errors.New("Buffer too small")
  }

  helloRetry := &HelloRetry{}
  copy(helloRetry.Cookie[:], buffer[:CookieSize])
  return helloRetry, CookieSize, nil
}

func DeserializeIntroduction(buffer []byte) (*Introduction, int, error) {
  if len(buffer) < IntroductionSize {
    return nil, -1, errors.New("Buffer too small")
  }

  introduction := &Introduction{}
  copy(introduction.PublicKeyDH[:], buffer[:PublicKeyDHSize])
  buffer = buffer[PublicKeyDHSize:]
  copy(introduction.SourcePublicKeyED[:], buffer[:PublicKeyEDSize])
  buffer = buffer[PublicKeyEDSize:]
  copy(introduction.SourceIP[:], buffer[:IPV6Size])
  buffer = buffer[IPV6Size:]
  introduction.SourcePort = binary.BigEndian.Uint16(buffer)
  buffer = buffer[PortSize:]
  copy(introduction.TargetPublicKeyED[:], buffer[:PublicKeyEDSize])
  buffer = buffer[PublicKeyEDSize:]
  copy(introduction.Signature[:], buffer[:SignatureSize])

  return introduction, IntroductionSize, nil
}

func DeserializeData(buffer []byte) (*Data, int, error) {
  if len(buffer) < DataHeaderSize {
    return nil, -1, errors.New("Buffer too small")
  }

  streamID := buffer[0]
  dataType := buffer[1]

  buffer = buffer[2:]

  sequenceNumber := binary.BigEndian.Uint32(buffer[:DataSequenceNumberSize])
  buffer = buffer[DataSequenceNumberSize:]

  ackNumber := binary.BigEndian.Uint32(buffer[:DataAckNumberSize])
  buffer = buffer[DataAckNumberSize:]

  if dataType == DataFinished {
    return &Data{
      StreamID: streamID,
      DataType: dataType,
      SequenceNumber: sequenceNumber,
      AckNumber: ackNumber,
      Data: nil,
    }, DataHeaderSize, nil
  }

  dataLength := binary.BigEndian.Uint16(buffer[:DataLengthSize])
  buffer = buffer[DataLengthSize:]

  if len(buffer) < int(dataLength) {
    return nil, -1, errors.New("Buffer too small")
  }

  data := &Data{
    StreamID: streamID,
    DataType: dataType,
    SequenceNumber: sequenceNumber,
    AckNumber: ackNumber,
    Data: buffer[:dataLength],
  }

  return data, DataHeaderSize + len(data.Data), nil
}

func (hello *Hello) Type() byte {
  return PacketHello
}

func (hello *Hello) Serialize(buffer []byte) (int, error) {
  if len(buffer) < hello.BufferSize() {
    return -1, errors.New("Buffer too small")
  }

  n := 0
  n += copy(buffer, []byte{Version, PacketHello})
  n += copy(buffer[n:], hello.PublicKeyDH[:])
  n += copy(buffer[n:], hello.PublicKeyED[:])
  n += copy(buffer[n:], hello.Signature[:])
  n += copy(buffer[n:], hello.Cookie[:])

  return n, nil
}

func (hello *Hello) BufferSize() int {
  return HelloSize + HeaderSize
}

func (helloRetry *HelloRetry) Type() byte {
  return PacketHelloRetry
}

func (helloRetry *HelloRetry) Serialize(buffer []byte) (int, error) {
  if len(buffer) < helloRetry.BufferSize() {
    return -1, errors.New("Buffer too small")
  }

  n := 0
  n += copy(buffer, []byte{Version, PacketHelloRetry})
  n += copy(buffer[n:], helloRetry.Cookie[:])

  return n, nil
}

func (helloRetry *HelloRetry) BufferSize() int {
  return CookieSize + HeaderSize
}

func (introduction *Introduction) Type() byte {
  return PacketIntroduction
}

func (introduction *Introduction) Serialize(buffer []byte) (int, error) {
  if len(buffer) < introduction.BufferSize() {
    return -1, errors.New("Buffer too small")
  }

  n := 0
  n += copy(buffer, []byte{Version, PacketIntroduction})
  n += copy(buffer[n:], introduction.PublicKeyDH[:])
  n += copy(buffer[n:], introduction.SourcePublicKeyED[:])
  n += copy(buffer[n:], introduction.SourceIP[:])
  binary.BigEndian.PutUint16(buffer[n:], introduction.SourcePort)
  n += PortSize
  n += copy(buffer[n:], introduction.TargetPublicKeyED[:])
  n += copy(buffer[n:], introduction.Signature[:])

  return n, nil
}

func (introduction *Introduction) BufferSize() int {
  return IntroductionSize + HeaderSize
}

func (data *Data) Type() byte {
  return PacketData
}

func (data *Data) Serialize(buffer []byte) (int, error) {
  if len(buffer) < data.BufferSize() {
    return -1, errors.New("Buffer too small")
  }

  n := 0
  n += copy(buffer, []byte{Version, PacketData})
  buffer[n] = data.StreamID
  n += 1
  buffer[n] = data.DataType
  n += 1
  binary.BigEndian.PutUint32(buffer[n:], data.SequenceNumber)
  n += DataSequenceNumberSize
  binary.BigEndian.PutUint32(buffer[n:], data.AckNumber)
  n += DataAckNumberSize

  if data.DataType == DataFinished {
    return n, nil
  }

  binary.BigEndian.PutUint16(buffer[n:], uint16(len(data.Data)))
  n += DataLengthSize
  n += copy(buffer[n:], data.Data)

  return n, nil
}

func (data *Data) BufferSize() int {
  if data.DataType == DataFinished {
    return DataHeaderSize + HeaderSize
  }
  return DataHeaderSize + DataLengthSize + len(data.Data) + HeaderSize
}

