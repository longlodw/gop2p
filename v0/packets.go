package v0

import (
	"encoding/binary"
	"errors"
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
  Flags byte
  PublicKeyDH [PublicKeyDHSize]byte
  PublicKeyED [PublicKeyEDSize]byte
  Signature [SignatureSize]byte
  IP [IPV6Size]byte
  Port uint16
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
  IntroductionSize = 1 + PublicKeyDHSize + PublicKeyEDSize + SignatureSize + IPV6Size + PortSize 
)

const (
  IntroductionIsSourceAddress = 1
)

type Packet interface {
  Type() byte
  Serialize([]byte) (int, error)
  BufferSize() int
}

func SerializePackets(packets []Packet) [][]byte {
  start := 0
  serializedBuffers := make([][]byte, 0)
  for start < len(packets) {
    end, bufferLen := nextPacketIndex(packets, start)
    buffer := make([]byte, bufferLen)
    n := 0
    for i := start; i < end; i++ {
      c, _ := packets[i].Serialize(buffer[n:])
      n += c
    }
    serializedBuffers = append(serializedBuffers, buffer)
    start = end
  }
  return serializedBuffers
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

func DeserializePackets(buffers []byte) ([]Packet, error) {
  packets := make([]Packet, 0)
  for len(buffers) > 0 {
    packet, n, err := DeserializePacket(buffers)
    if err != nil {
      return packets, err
    }
    packets = append(packets, packet)
    buffers = buffers[n:]
  }
  return packets, nil
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
  introduction.Flags = buffer[0]
  buffer = buffer[1:]
  copy(introduction.PublicKeyDH[:], buffer[:PublicKeyDHSize])
  buffer = buffer[PublicKeyDHSize:]
  copy(introduction.PublicKeyED[:], buffer[:PublicKeyEDSize])
  buffer = buffer[PublicKeyEDSize:]
  copy(introduction.Signature[:], buffer[:SignatureSize])
  buffer = buffer[SignatureSize:]
  copy(introduction.IP[:], buffer[:IPV6Size])
  buffer = buffer[IPV6Size:]
  introduction.Port = binary.BigEndian.Uint16(buffer)
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
  buffer[n] = introduction.Flags
  n += 1
  n += copy(buffer[n:], introduction.PublicKeyDH[:])
  n += copy(buffer[n:], introduction.PublicKeyED[:])
  n += copy(buffer[n:], introduction.Signature[:])
  n += copy(buffer[n:], introduction.IP[:])
  binary.BigEndian.PutUint16(buffer[n:], introduction.Port)
  n += PortSize

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

