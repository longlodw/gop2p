package v0

import (
  "encoding/binary"
  "errors"
  "io"
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

func ParsePacketHeader(r io.Reader) (version byte, packetType byte, length uint16, err error) {
  buffer := make([]byte, HeaderSize)
  nums, err := r.Read(buffer)
  if err != nil {
    return 0, 0, 0, err
  }
  if nums != HeaderSize {
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

func ParseHello(r io.Reader) (publicKeyDH [32]byte, publicKeyED [32]byte, dynamicIP bool, cookie [32]byte, signature [64]byte, err error) {
  nums, err := r.Read(publicKeyDH[:])
  if err != nil {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err
  }
  if nums != 32 {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, errors.New("public key dh size error")
  }

  nums, err = r.Read(publicKeyED[:])
  if err != nil {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err
  }
  if nums != 32 {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, errors.New("public key ed size error")
  }

  dynamicIPByte := make([]byte, 1)
  nums, err = r.Read(dynamicIPByte)
  if err != nil {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err
  }
  if nums != 1 {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, errors.New("dynamic ip size error")
  }
  dynamicIP = dynamicIPByte[0] == 1

  nums, err = r.Read(cookie[:])
  if err != nil {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err
  }
  if nums != 32 {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, errors.New("cookie size error")
  }

  nums, err = r.Read(signature[:])
  if err != nil {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err
  }
  if nums != 64 {
    return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, errors.New("signature size error")
  }
  return publicKeyDH, publicKeyED, dynamicIP, cookie, signature, nil
}

func ParsePing(r io.Reader) (cookie [32]byte, err error) {
  nums, err := r.Read(cookie[:])
  if err != nil {
    return cookie, err
  }
  if nums != 32 {
    return cookie, errors.New("cookie size error")
  }
  return cookie, nil
}

// when parsing data, we need to parse the data header first
// using the data header, we can determine the stream id and data type and then parse the data
func ParseDataHeader(r io.Reader) (streamID byte, dataType byte, err error) {
  buffer := make([]byte, 2)
  nums, err := r.Read(buffer)
  if err != nil {
    return 0, 0, err
  }
  if nums != 2 {
    return 0, 0, errors.New("data header size error")
  }
  return buffer[0], buffer[1], nil
}

func ParseReliableDataHeader(r io.Reader) (length uint16, sequenceNumber uint32, ackNumber uint32, err error) {
  buffer := make([]byte, 10)
  nums, err := r.Read(buffer)
  if err != nil {
    return 0, 0, 0, err
  }
  if nums != 10 {
    return 0, 0, 0, errors.New("reliable data header size error")
  }
  length = binary.BigEndian.Uint16(buffer)
  sequenceNumber = binary.BigEndian.Uint32(buffer[2:])
  ackNumber = binary.BigEndian.Uint32(buffer[4:])
  return length, sequenceNumber, ackNumber, nil
}

func ParseUnreliableDataHeader(r io.Reader) (length uint16, err error) {
  buffer := make([]byte, 2)
  nums, err := r.Read(buffer)
  if err != nil {
    return 0, err
  }
  if nums != 2 {
    return 0, errors.New("unreliable data header size error")
  }
  return binary.BigEndian.Uint16(buffer), nil
}

func ParseUnreliableDataAckHeader(r io.Reader) (length uint16, ackNumber uint32, err error) {
  buffer := make([]byte, 6)
  nums, err := r.Read(buffer)
  if err != nil {
    return 0, 0, err
  }
  if nums != 6 {
    return 0, 0, errors.New("unreliable data ack header size error")
  }
  length = binary.BigEndian.Uint16(buffer)
  ackNumber = binary.BigEndian.Uint32(buffer[2:])
  return length, ackNumber, nil
}

func ParseIntroductionRequest(r io.Reader) (publicKeyDH [32]byte, publicKeyED [32]byte, dynamicIP bool, cookie [32]byte, signature [64]byte, err error) {
  return ParseHello(r)
}

func ParseIntroductionAck(r io.Reader) (status byte, err error) {
  buffer := make([]byte, 1)
  nums, err := r.Read(buffer)
  if err != nil {
    return 0, err
  }
  if nums != 1 {
    return 0, errors.New("status size error")
  }
  return buffer[0], nil
}

func ParseIntroduction(r io.Reader) (ipv6 [16]byte, port uint16, publicKeyDH [32]byte, publicKeyED [32]byte, dynamicIP bool, cookie [32]byte, signature [64]byte, err error) {
  nums, err := r.Read(ipv6[:])
  if err != nil {
    return ipv6, port, publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err
  }
  if nums != 16 {
    return ipv6, port, publicKeyDH, publicKeyED, dynamicIP, cookie, signature, errors.New("ipv6 size error")
  }

  buffer := make([]byte, 2)
  nums, err = r.Read(buffer)
  if err != nil {
    return ipv6, port, publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err
  }
  if nums != 2 {
    return ipv6, port, publicKeyDH, publicKeyED, dynamicIP, cookie, signature, errors.New("port size error")
  }
  port = binary.BigEndian.Uint16(buffer)
  publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err = ParseHello(r)
  return ipv6, port, publicKeyDH, publicKeyED, dynamicIP, cookie, signature, err
}

