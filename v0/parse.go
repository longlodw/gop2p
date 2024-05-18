package v0

import (
  "encoding/binary"
  "errors"
)

// constants
const (
  // version
  Version0 = 0
  // version size
  VersionSize = 1
  // packet type size
  PacketTypeSize = 1
  // length size
  PacketLengthSize = 2
  // packet header size
  HeaderSize = VersionSize + PacketTypeSize + PacketLengthSize
  // packet type
  PacketHello = 0
  PacketPing = 1
  PacketData = 2
  // data type
  DataReliable = 0
  DataUnreliable = 1
  DataUnreliableAck = 2
  DataPeerListRequest = 3
  DataIntroductionRequest = 4
  DataIntroductionAck = 5
  DataIntroduction = 6
  // introduction status
  IntroductionStatusOK = 0
  IntroductionStatusInvalidParams = 1
  IntroductionStatusUnknownPeer = 2
)

func ParsePacketHeader(buffer []byte) (version byte, packetType byte, length uint16, err error) {
  if len(buffer) < HeaderSize {
    return 0, 0, 0, errors.New("header size error")
  }
  version = buffer[0]
  if version != Version0 {
    return 0, 0, 0, errors.New("version error")
  }
  packetType = buffer[VersionSize]
  length = binary.BigEndian.Uint16(buffer[VersionSize+PacketTypeSize:])
  return version, packetType, length, nil
}

func ParseHello(buffer []byte) (publicKeyDH []byte, publicKeyED []byte, dynamicIP bool, cookie []byte, signature []byte, err error) {
  if len(buffer) < 129 {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, errors.New("hello size error")
  }
  publicKeyDH = buffer[:32]
  publicKeyED = buffer[32:64]
  dynamicIP = buffer[64] == 1
  cookie = buffer[65:97]
  signature = buffer[97:161]
  return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, nil
}

func ParsePing(buffer []byte) (cookie []byte, err error) {
  if len(buffer) < 32 {
    return cookie, errors.New("ping size error")
  }
  cookie = buffer
  return cookie, nil
}

// when parsing data, we need to parse the data header first
// using the data header, we can determine the stream id and data type and then parse the data
func ParseDataHeader(buffer []byte) (streamID byte, dataType byte, err error) {
  if len(buffer) < 2 {
    return 0, 0, errors.New("data header size error")
  }
  return buffer[0], buffer[1], nil
}

func ParseReliableDataHeader(buffer []byte) (length uint16, sequenceNumber uint32, ackNumber uint32, err error) {
  if len(buffer) < 10 {
    return 0, 0, 0, errors.New("reliable data header size error")
  }
  length = binary.BigEndian.Uint16(buffer)
  sequenceNumber = binary.BigEndian.Uint32(buffer[2:])
  ackNumber = binary.BigEndian.Uint32(buffer[4:])
  return length, sequenceNumber, ackNumber, nil
}

func ParseUnreliableDataHeader(buffer []byte) (length uint16, err error) {
  if len(buffer) < 2 {
    return 0, errors.New("unreliable data header size error")
  }
  return binary.BigEndian.Uint16(buffer), nil
}

func ParseUnreliableDataAckHeader(buffer []byte) (length uint16, ackNumber uint32, err error) {
  if len(buffer) < 6 {
    return 0, 0, errors.New("unreliable data ack header size error")
  }
  length = binary.BigEndian.Uint16(buffer)
  ackNumber = binary.BigEndian.Uint32(buffer[2:])
  return length, ackNumber, nil
}

func ParseIntroductionRequest(buffer []byte) (publicKeyDH []byte, publicKeyED []byte, dynamicIP bool, cookie []byte, signature []byte, err error) {
  return ParseHello(buffer)
}

func ParseIntroductionAck(buffer []byte) (status byte, err error) {
  if len(buffer) < 1 {
    return 0, errors.New("introduction ack size error")
  }
  return buffer[0], nil
}

func ParseIntroduction(buffer []byte) (ipv6 []byte, port uint16, publicKeyDH []byte, publicKeyED []byte, dynamicIP bool, cookie []byte, signature []byte, err error) {
  if len(buffer) < 146 {
    return ipv6, port, publicKeyDH, publicKeyED, dynamicIP, cookie, signature, errors.New("introduction size error")
  }
  ipv6 = buffer[:16]
  port = binary.BigEndian.Uint16(buffer[16:])
  publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err = ParseHello(buffer[18:])
  return ipv6, port, publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err
}

