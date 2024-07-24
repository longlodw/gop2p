package gop2p

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"testing"
)

func TestHello(t *testing.T) {
  publicKeyDH := [PublicKeyDHSize]byte{}
  publicKeyED := [PublicKeyEDSize]byte{}
  signature := [SignatureSize]byte{}
  cookie := [CookieSize]byte{}
  _, err := rand.Read(publicKeyDH[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(publicKeyED[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(signature[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(cookie[:])
  if err != nil {
    t.Fatal(err)
  }
  hello := Hello{
    PublicKeyDH: publicKeyDH,
    PublicKeyED: publicKeyED,
    Signature: signature,
    Cookie: cookie,
  }
  buffer := make([]byte, hello.BufferSize())
  n, err := hello.Serialize(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when serializing", len(buffer), n)
  }
  p, n, err := DeserializePacket(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when deserialize", len(buffer), n)
  }
  hello2, ok := p.(*Hello)
  if !ok {
    t.Fatalf("Expected %T, got %T", hello, p)
  }
  if hello.PublicKeyDH != hello2.PublicKeyDH {
    t.Fatalf("Expected %v, got %v", hello.PublicKeyDH, hello2.PublicKeyDH)
  }
  if hello.PublicKeyED != hello2.PublicKeyED {
    t.Fatalf("Expected %v, got %v", hello.PublicKeyED, hello2.PublicKeyED)
  }
  if hello.Signature != hello2.Signature {
    t.Fatalf("Expected %v, got %v", hello.Signature, hello2.Signature)
  }
  if hello.Cookie != hello2.Cookie {
    t.Fatalf("Expected %v, got %v", hello.Cookie, hello2.Cookie)
  }
}

func TestHelloRetry(t *testing.T) {
  cookie := [CookieSize]byte{}
  _, err := rand.Read(cookie[:])
  if err != nil {
    t.Fatal(err)
  }
  helloRetry := HelloRetry{
    Cookie: cookie,
  }
  buffer := make([]byte, helloRetry.BufferSize())
  n, err := helloRetry.Serialize(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when serializing", len(buffer), n)
  }
  p, n, err := DeserializePacket(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when deserialize", len(buffer), n)
  }
  helloRetry2, ok := p.(*HelloRetry)
  if !ok {
    t.Fatalf("Expected %T, got %T", helloRetry, p)
  }
  if helloRetry.Cookie != helloRetry2.Cookie {
    t.Fatalf("Expected %v, got %v", helloRetry.Cookie, helloRetry2.Cookie)
  }
}

func TestIntroduction(t *testing.T) {
  publicKeyDH := [PublicKeyDHSize]byte{}
  publicKeyED := [PublicKeyEDSize]byte{}
  signature := [SignatureSize]byte{}
  ip := [IPV6Size]byte{}
  port := [PortSize]byte{}

  _, err := rand.Read(publicKeyDH[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(publicKeyED[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(signature[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(ip[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(port[:])
  if err != nil {
    t.Fatal(err)
  }
  portValue := binary.BigEndian.Uint16(port[:])
  introduction := Introduction{
    Flags: 0,
    PublicKeyDH: publicKeyDH,
    PublicKeyED: publicKeyED,
    Signature: signature,
    IP: ip,
    Port: portValue,
  }
  buffer := make([]byte, introduction.BufferSize())
  n, err := introduction.Serialize(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when serializing", len(buffer), n)
  }
  p, n, err := DeserializePacket(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when deserialize", len(buffer), n)
  }
  introduction2, ok := p.(*Introduction)
  if !ok {
    t.Fatalf("Expected %T, got %T", introduction, p)
  }
  if introduction.Flags != introduction2.Flags {
    t.Fatalf("Expected %v, got %v", introduction.Flags, introduction2.Flags)
  }
  if introduction.PublicKeyDH != introduction2.PublicKeyDH {
    t.Fatalf("Expected %v, got %v", introduction.PublicKeyDH, introduction2.PublicKeyDH)
  }
  if introduction.PublicKeyED != introduction2.PublicKeyED {
    t.Fatalf("Expected %v, got %v", introduction.PublicKeyED, introduction2.PublicKeyED)
  }
  if introduction.Signature != introduction2.Signature {
    t.Fatalf("Expected %v, got %v", introduction.Signature, introduction2.Signature)
  }
  if introduction.IP != introduction2.IP {
    t.Fatalf("Expected %v, got %v", introduction.IP, introduction2.IP)
  }
  if introduction.Port != introduction2.Port {
    t.Fatalf("Expected %v, got %v", introduction.Port, introduction2.Port)
  }
}

func TestData(t *testing.T) {
  streamID := [1]byte{}
  sequenceNumber := [4]byte{}
  ackNumber := [4]byte{}
  data := make([]byte, MaxDataSize)
  _, err := rand.Read(streamID[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(sequenceNumber[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(ackNumber[:])
  if err != nil {
    t.Fatal(err)
  }
  _, err = rand.Read(data[:])
  if err != nil {
    t.Fatal(err)
  }

  streamIDValue := streamID[0]
  dataTypeValue := DataAck
  sequenceNumberValue := binary.BigEndian.Uint32(sequenceNumber[:])
  ackNumberValue := binary.BigEndian.Uint32(ackNumber[:])
  dataPacket := Data{
    StreamID: streamIDValue,
    DataType: dataTypeValue,
    SequenceNumber: sequenceNumberValue,
    AckNumber: ackNumberValue,
    Data: data,
  }
  buffer := make([]byte, dataPacket.BufferSize())
  n, err := dataPacket.Serialize(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when serializing", len(buffer), n)
  }
  p, n, err := DeserializePacket(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when deserialize", len(buffer), n)
  }
  dataPacket2, ok := p.(*Data)
  if !ok {
    t.Fatalf("Expected %T, got %T", dataPacket, p)
  }
  if dataPacket.SequenceNumber != dataPacket2.SequenceNumber {
    t.Fatalf("Expected %v, got %v", dataPacket.SequenceNumber, dataPacket2.SequenceNumber)
  }
  if dataPacket.DataType != dataPacket2.DataType {
    t.Fatalf("Expected %v, got %v", dataPacket.DataType, dataPacket2.DataType)
  }
  if !bytes.Equal(dataPacket.Data, dataPacket2.Data) {
    t.Fatalf("Expected %v, got %v", dataPacket.Data, dataPacket2.Data)
  }
}

func TestSerialzeDeserializePackets(t *testing.T) {
  packets := make([]Packet, 0)
  expectedTotalLen := 0
  for i := 0; i < 10; i++ {
    streamID := [1]byte{}
    sequenceNumber := [4]byte{}
    ackNumber := [4]byte{}
    data := make([]byte, mrand.Intn(MaxDataSize))
    _, err := rand.Read(streamID[:])
    if err != nil {
      t.Fatal(err)
    }
    _, err = rand.Read(sequenceNumber[:])
    if err != nil {
      t.Fatal(err)
    }
    _, err = rand.Read(ackNumber[:])
    if err != nil {
      t.Fatal(err)
    }
    _, err = rand.Read(data[:])
    if err != nil {
      t.Fatal(err)
    }

    streamIDValue := streamID[0]
    dataTypeValue := DataAck
    sequenceNumberValue := binary.BigEndian.Uint32(sequenceNumber[:])
    ackNumberValue := binary.BigEndian.Uint32(ackNumber[:])
    dataPacket := &Data{
      StreamID: streamIDValue,
      DataType: dataTypeValue,
      SequenceNumber: sequenceNumberValue,
      AckNumber: ackNumberValue,
      Data: data,
    }
    expectedTotalLen += dataPacket.BufferSize()
    packets = append(packets, dataPacket)
  }
  buffers := SerializePackets(packets)

  totalLen := 0
  for _, e := range buffers {
    totalLen += len(e)
  }
  if totalLen != expectedTotalLen {
    t.Fatalf("Wrong total length of buffer: Expected %v, got %v", expectedTotalLen, totalLen)
  }
  
  deserializedPackets := make([]Packet, 0)
  for _, buffer := range buffers {
    dPackets, err := DeserializePackets(buffer)
    if err != nil {
      t.Fatal(err)
    }
    deserializedPackets = append(deserializedPackets, dPackets...)
  }

  for k := 0; k < len(deserializedPackets); k++ {
    p := deserializedPackets[k]
    packet, ok := p.(*Data)
    if !ok {
      t.Fatalf("Wrong packet type: Expected %T, got %T", &Data{}, p)
    }
    if packet.SequenceNumber != packets[k].(*Data).SequenceNumber {
      t.Fatalf("Wrong sequence number: Expected %v, got %v", packet.SequenceNumber, packets[k].(*Data).SequenceNumber)
    }
    if packet.AckNumber != packets[k].(*Data).AckNumber {
      t.Fatalf("Wrong ack number: Expected %v, got %v", packet.AckNumber, packets[k].(*Data).AckNumber)
    }
    if packet.DataType != packets[k].(*Data).DataType {
      t.Fatalf("Wrong data type: Expected %v, got %v", packet.DataType, packets[k].(*Data).DataType)
    }
    if !bytes.Equal(packet.Data, packets[k].(*Data).Data) {
      t.Fatalf("Wrong data: Expected %v, got %v", packet.Data, packets[k].(*Data).Data)
    }
  }
}
