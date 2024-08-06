package gop2p

import (
	"crypto/rand"
	"encoding/binary"
)

type hello struct {
  publicKeyDH [PublicKeyDHSize]byte
  publicKeyED [PublicKeyEDSize]byte
  signature [SignatureSize]byte
  cookie [CookieSize]byte
}

type helloRetry struct {
  cookie [CookieSize]byte
}

type introduction struct {
  flags byte
  publicKeyDH [PublicKeyDHSize]byte
  publicKeyED [PublicKeyEDSize]byte
  signature [SignatureSize]byte
  ip [IPV6Size]byte
  port uint16
}

type data struct {
  streamID byte
  dataType byte
  ackNumber uint32
  sequenceNumber uint32
  data []byte
}

type connectionClosed struct {}

const (
  Version = 0
  MaxPacketSize = 1184
)

const (
  PacketHello byte = iota
  PacketHelloRetry
  PacketIntroduction
  PacketData
  PacketConnectionClosed
)

const (
  DataAck byte = 1
  DataClosed byte = 2
  DataNewStream byte = 4
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
  DataHeaderSize = DataIDSize + DataTypeSize + DataSequenceNumberSize + DataAckNumberSize + DataLengthSize
  DataLengthSize = 2
  MaxDataSize = MaxPacketSize - DataHeaderSize - 16
)

const (
  VersionSize = 1
  PacketTypeSize = 1
  PaddingSize = 1
  HeaderSize = VersionSize + PacketTypeSize + PaddingSize
  HelloSize = PublicKeyDHSize + PublicKeyEDSize + SignatureSize + CookieSize
  IntroductionSize = 1 + PublicKeyDHSize + PublicKeyEDSize + SignatureSize + IPV6Size + PortSize 
)

const (
  IntroductionIsSourceAddress = 1
)

type packet interface {
  Type() byte
  Serialize([]byte) (int, error)
  BufferSize() int
}

func serializePackets(packets []packet) [][]byte {
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

func nextPacketIndex(packets []packet, start int) (int, int) {
  bufferLen := 0
  for i := start; i < len(packets); i++ {
    if packets[i].BufferSize() + bufferLen > MaxPacketSize {
      return i, bufferLen
    }
    bufferLen += packets[i].BufferSize()
  }
  return len(packets), bufferLen
}

func deserializePackets(buffer []byte) ([]packet, error) {
  packets := make([]packet, 0)
  for k := 0; k < len(buffer); {
    packet, n, err := deserializePacket(buffer[k:])
    if err != nil {
      return packets, err
    }
    end := k + n
    packets = append(packets, packet)
    k = end
  }
  return packets, nil
}

func deserializePacket(buffer []byte) (packet, int, error) {
  if len(buffer) < HeaderSize {
    return nil, -1, newInvalidPacketError("Buffer too small")
  }

  if buffer[0] != Version {
    return nil, -1, newInvalidPacketError("Invalid version")
  }

  packetType := buffer[1]
  paddingSize := buffer[2]
  buffer = buffer[HeaderSize:]

  switch packetType {
  case PacketHello:
    p, n, err := deserializeHello(buffer)
    return p, n + HeaderSize, err
  case PacketHelloRetry:
    p, n, err := deserializeHelloRetry(buffer)
    return p, n + HeaderSize, err
  case PacketIntroduction:
    p, n, err := deserializeIntroduction(buffer)
    return p, n + HeaderSize + int(paddingSize), err
  case PacketData:
    p, n, err := deserializeData(buffer)
    return p, n + HeaderSize + int(paddingSize), err
  case PacketConnectionClosed:
    p, n, err := deserializeConnectionClosed(buffer)
    return p, n + HeaderSize + int(paddingSize), err
  default:
    return nil, -1, newInvalidPacketError("Invalid packet type")
  }
}

func deserializeHello(buffer []byte) (*hello, int, error) {
  if len(buffer) < HelloSize {
    return nil, -1, newInvalidPacketError("Buffer too small")
  }

  hello := &hello{}
  copy(hello.publicKeyDH[:], buffer[:PublicKeyDHSize])
  buffer = buffer[PublicKeyDHSize:]
  copy(hello.publicKeyED[:], buffer[:PublicKeyEDSize])
  buffer = buffer[PublicKeyEDSize:]
  copy(hello.signature[:], buffer[:SignatureSize])
  buffer = buffer[SignatureSize:]
  copy(hello.cookie[:], buffer[:CookieSize])

  return hello, HelloSize, nil
}

func deserializeHelloRetry(buffer []byte) (*helloRetry, int, error) {
  if len(buffer) < CookieSize {
    return nil, -1, newInvalidPacketError("Buffer too small")
  }

  helloRetry := &helloRetry{}
  copy(helloRetry.cookie[:], buffer[:CookieSize])
  return helloRetry, CookieSize, nil
}

func deserializeIntroduction(buffer []byte) (*introduction, int, error) {
  if len(buffer) < IntroductionSize {
    return nil, -1, newInvalidPacketError("Buffer too small")
  }

  introduction := &introduction{}
  introduction.flags = buffer[0]
  buffer = buffer[1:]
  copy(introduction.publicKeyDH[:], buffer[:PublicKeyDHSize])
  buffer = buffer[PublicKeyDHSize:]
  copy(introduction.publicKeyED[:], buffer[:PublicKeyEDSize])
  buffer = buffer[PublicKeyEDSize:]
  copy(introduction.signature[:], buffer[:SignatureSize])
  buffer = buffer[SignatureSize:]
  copy(introduction.ip[:], buffer[:IPV6Size])
  buffer = buffer[IPV6Size:]
  introduction.port = binary.BigEndian.Uint16(buffer)
  return introduction, IntroductionSize, nil
}

func deserializeData(buffer []byte) (*data, int, error) {
  if len(buffer) < DataHeaderSize {
    return nil, -1, newInvalidPacketError("Buffer too small")
  }

  l := 0
  dataPacket := &data{}
  dataPacket.streamID = buffer[0]
  dataPacket.dataType = buffer[1]
  buffer = buffer[2:]
  l += 2

  dataPacket.sequenceNumber = binary.BigEndian.Uint32(buffer[:DataSequenceNumberSize])
  buffer = buffer[DataSequenceNumberSize:]
  l += DataSequenceNumberSize

  dataPacket.ackNumber = binary.BigEndian.Uint32(buffer[:DataAckNumberSize])
  buffer = buffer[DataAckNumberSize:]
  l += DataAckNumberSize

  dataLength := binary.BigEndian.Uint16(buffer[:DataLengthSize])
  buffer = buffer[DataLengthSize:]
  l += DataLengthSize

  if dataPacket.dataType & DataClosed != 0 {
    return dataPacket, l, nil
  }
  if len(buffer) < int(dataLength) {
    return nil, -1, newInvalidPacketError("Buffer too small")
  }
  dataPacket.data = make([]byte, dataLength)
  copy(dataPacket.data, buffer[:dataLength])
  l += int(dataLength)

  return dataPacket, l, nil
}

func deserializeConnectionClosed(_ []byte) (*connectionClosed, int, error) {
  return &connectionClosed{}, 0, nil
}

func (hello *hello) Type() byte {
  return PacketHello
}

func (hello *hello) Serialize(buffer []byte) (int, error) {
  if len(buffer) < hello.BufferSize() {
    return -1, newInvalidPacketError("Buffer too small")
  }

  n := 0
  n += copy(buffer, []byte{Version, PacketHello, 0})
  n += copy(buffer[n:], hello.publicKeyDH[:])
  n += copy(buffer[n:], hello.publicKeyED[:])
  n += copy(buffer[n:], hello.signature[:])
  n += copy(buffer[n:], hello.cookie[:])

  return n, nil
}

func (hello *hello) BufferSize() int {
  return HelloSize + HeaderSize
}

func (helloRetry *helloRetry) Type() byte {
  return PacketHelloRetry
}

func (helloRetry *helloRetry) Serialize(buffer []byte) (int, error) {
  if len(buffer) < helloRetry.BufferSize() {
    return -1, newInvalidPacketError("Buffer too small")
  }

  n := 0
  n += copy(buffer, []byte{Version, PacketHelloRetry, 0})
  n += copy(buffer[n:], helloRetry.cookie[:])

  return n, nil
}

func (helloRetry *helloRetry) BufferSize() int {
  return CookieSize + HeaderSize
}

func (introduction *introduction) Type() byte {
  return PacketIntroduction
}

func (introduction *introduction) Serialize(buffer []byte) (int, error) {
  if len(buffer) < introduction.BufferSize() {
    return -1, newInvalidPacketError("Buffer too small")
  }

  n := 0
  var paddingSize uint8 = 10
  n += copy(buffer, []byte{Version, PacketIntroduction, paddingSize})
  buffer[n] = introduction.flags
  n += 1
  n += copy(buffer[n:], introduction.publicKeyDH[:])
  n += copy(buffer[n:], introduction.publicKeyED[:])
  n += copy(buffer[n:], introduction.signature[:])
  n += copy(buffer[n:], introduction.ip[:])
  binary.BigEndian.PutUint16(buffer[n:], introduction.port)
  n += PortSize
  rand.Read(buffer[n:n+int(paddingSize)])
  n += int(paddingSize)

  return n, nil
}

func (introduction *introduction) BufferSize() int {
  const paddingSize = 10
  return IntroductionSize + HeaderSize + paddingSize
}

func (data *data) Type() byte {
  return PacketData
}

func (data *data) Serialize(buffer []byte) (int, error) {
  if len(buffer) < data.BufferSize() {
    return -1, newInvalidPacketError("Buffer too small")
  }

  n := 0
  n += copy(buffer, []byte{Version, PacketData, 0})
  buffer[n] = data.streamID
  n += 1
  buffer[n] = data.dataType
  n += 1
  binary.BigEndian.PutUint32(buffer[n:], data.sequenceNumber)
  n += DataSequenceNumberSize
  binary.BigEndian.PutUint32(buffer[n:], data.ackNumber)
  n += DataAckNumberSize

  binary.BigEndian.PutUint16(buffer[n:], uint16(len(data.data)))
  n += DataLengthSize
  if data.dataType & DataClosed == 0 {
    n += copy(buffer[n:], data.data)
  }
  buffer[2] = byte((16 - n % 16) % 16)
  rand.Read(buffer[n:n+int(buffer[2])])
  n += int(buffer[2])
  return n, nil
}

func (data *data) BufferSize() int {
  if data.dataType & DataClosed != 0 {
    return DataHeaderSize + HeaderSize + 1
  }
  n := DataHeaderSize + HeaderSize
  if data.dataType & DataClosed != 0 {
    return n + 1
  }
  required := n + len(data.data)
  return required + (16 - required % 16) % 16
}

func (connClosed *connectionClosed) Type() byte {
  return PacketConnectionClosed
}

func (connClosed *connectionClosed) Serialize(buffer []byte) (int, error) {
  if len(buffer) < connClosed.BufferSize() {
    return -1, newInvalidPacketError("Buffer too small")
  }

  n := 0
  n += copy(buffer, []byte{Version, PacketConnectionClosed, 13})
  rand.Read(buffer[n:n+13])
  n += 13
  return n, nil
}

func (connClosed *connectionClosed) BufferSize() int {
  return HeaderSize + 13
}
