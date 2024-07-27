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
  hello1 := hello{
    publicKeyDH: publicKeyDH,
    publicKeyED: publicKeyED,
    signature: signature,
    cookie: cookie,
  }
  buffer := make([]byte, hello1.BufferSize())
  n, err := hello1.Serialize(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when serializing", len(buffer), n)
  }
  p, n, err := deserializePacket(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when deserialize", len(buffer), n)
  }
  hello2, ok := p.(*hello)
  if !ok {
    t.Fatalf("Expected %T, got %T", hello1, p)
  }
  if hello1.publicKeyDH != hello2.publicKeyDH {
    t.Fatalf("Expected %v, got %v", hello1.publicKeyDH, hello2.publicKeyDH)
  }
  if hello1.publicKeyED != hello2.publicKeyED {
    t.Fatalf("Expected %v, got %v", hello1.publicKeyED, hello2.publicKeyED)
  }
  if hello1.signature != hello2.signature {
    t.Fatalf("Expected %v, got %v", hello1.signature, hello2.signature)
  }
  if hello1.cookie != hello2.cookie {
    t.Fatalf("Expected %v, got %v", hello1.cookie, hello2.cookie)
  }
}

func TestHelloRetry(t *testing.T) {
  cookie := [CookieSize]byte{}
  _, err := rand.Read(cookie[:])
  if err != nil {
    t.Fatal(err)
  }
  helloRetry1 := helloRetry{
    cookie: cookie,
  }
  buffer := make([]byte, helloRetry1.BufferSize())
  n, err := helloRetry1.Serialize(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when serializing", len(buffer), n)
  }
  p, n, err := deserializePacket(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when deserialize", len(buffer), n)
  }
  helloRetry2, ok := p.(*helloRetry)
  if !ok {
    t.Fatalf("Expected %T, got %T", helloRetry1, p)
  }
  if helloRetry1.cookie != helloRetry2.cookie {
    t.Fatalf("Expected %v, got %v", helloRetry1.cookie, helloRetry2.cookie)
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
  introduction1 := introduction{
    flags: 0,
    publicKeyDH: publicKeyDH,
    publicKeyED: publicKeyED,
    signature: signature,
    ip: ip,
    port: portValue,
  }
  buffer := make([]byte, introduction1.BufferSize())
  n, err := introduction1.Serialize(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when serializing", len(buffer), n)
  }
  p, n, err := deserializePacket(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when deserialize", len(buffer), n)
  }
  introduction2, ok := p.(*introduction)
  if !ok {
    t.Fatalf("Expected %T, got %T", introduction1, p)
  }
  if introduction1.flags != introduction2.flags {
    t.Fatalf("Expected %v, got %v", introduction1.flags, introduction2.flags)
  }
  if introduction1.publicKeyDH != introduction2.publicKeyDH {
    t.Fatalf("Expected %v, got %v", introduction1.publicKeyDH, introduction2.publicKeyDH)
  }
  if introduction1.publicKeyED != introduction2.publicKeyED {
    t.Fatalf("Expected %v, got %v", introduction1.publicKeyED, introduction2.publicKeyED)
  }
  if introduction1.signature != introduction2.signature {
    t.Fatalf("Expected %v, got %v", introduction1.signature, introduction2.signature)
  }
  if introduction1.ip != introduction2.ip {
    t.Fatalf("Expected %v, got %v", introduction1.ip, introduction2.ip)
  }
  if introduction1.port != introduction2.port {
    t.Fatalf("Expected %v, got %v", introduction1.port, introduction2.port)
  }
}

func TestData(t *testing.T) {
  streamID := [1]byte{}
  sequenceNumber := [4]byte{}
  ackNumber := [4]byte{}
  dataBuf := make([]byte, MaxDataSize)
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
  _, err = rand.Read(dataBuf[:])
  if err != nil {
    t.Fatal(err)
  }

  streamIDValue := streamID[0]
  dataTypeValue := DataAck
  sequenceNumberValue := binary.BigEndian.Uint32(sequenceNumber[:])
  ackNumberValue := binary.BigEndian.Uint32(ackNumber[:])
  dataPacket := data{
    streamID: streamIDValue,
    dataType: dataTypeValue,
    sequenceNumber: sequenceNumberValue,
    ackNumber: ackNumberValue,
    data: dataBuf,
  }
  buffer := make([]byte, dataPacket.BufferSize())
  n, err := dataPacket.Serialize(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when serializing", len(buffer), n)
  }
  p, n, err := deserializePacket(buffer)
  if err != nil {
    t.Fatal(err)
  }
  if n != len(buffer) {
    t.Fatalf("Expected %d, got %d when deserialize", len(buffer), n)
  }
  dataPacket2, ok := p.(*data)
  if !ok {
    t.Fatalf("Expected %T, got %T", dataPacket, p)
  }
  if dataPacket.sequenceNumber != dataPacket2.sequenceNumber {
    t.Fatalf("Expected %v, got %v", dataPacket.sequenceNumber, dataPacket2.sequenceNumber)
  }
  if dataPacket.dataType != dataPacket2.dataType {
    t.Fatalf("Expected %v, got %v", dataPacket.dataType, dataPacket2.dataType)
  }
  if !bytes.Equal(dataPacket.data, dataPacket2.data) {
    t.Fatalf("Expected %v, got %v", dataPacket.data, dataPacket2.data)
  }
}

func TestSerialzeDeserializePackets(t *testing.T) {
  packets := make([]packet, 0)
  expectedTotalLen := 0
  for i := 0; i < 10; i++ {
    streamID := [1]byte{}
    sequenceNumber := [4]byte{}
    ackNumber := [4]byte{}
    dataBuf := make([]byte, mrand.Intn(MaxDataSize))
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
    _, err = rand.Read(dataBuf[:])
    if err != nil {
      t.Fatal(err)
    }

    streamIDValue := streamID[0]
    dataTypeValue := DataAck
    sequenceNumberValue := binary.BigEndian.Uint32(sequenceNumber[:])
    ackNumberValue := binary.BigEndian.Uint32(ackNumber[:])
    dataPacket := &data{
      streamID: streamIDValue,
      dataType: dataTypeValue,
      sequenceNumber: sequenceNumberValue,
      ackNumber: ackNumberValue,
      data: dataBuf,
    }
    expectedTotalLen += dataPacket.BufferSize()
    packets = append(packets, dataPacket)
  }
  buffers := serializePackets(packets)

  totalLen := 0
  for _, e := range buffers {
    totalLen += len(e)
  }
  if totalLen != expectedTotalLen {
    t.Fatalf("Wrong total length of buffer: Expected %v, got %v", expectedTotalLen, totalLen)
  }
  
  deserializedPackets := make([]packet, 0)
  for _, buffer := range buffers {
    dPackets, err := deserializePackets(buffer)
    if err != nil {
      t.Fatal(err)
    }
    deserializedPackets = append(deserializedPackets, dPackets...)
  }

  for k := 0; k < len(deserializedPackets); k++ {
    p := deserializedPackets[k]
    packet, ok := p.(*data)
    if !ok {
      t.Fatalf("Wrong packet type: Expected %T, got %T", &data{}, p)
    }
    if packet.sequenceNumber != packets[k].(*data).sequenceNumber {
      t.Fatalf("Wrong sequence number: Expected %v, got %v", packet.sequenceNumber, packets[k].(*data).sequenceNumber)
    }
    if packet.ackNumber != packets[k].(*data).ackNumber {
      t.Fatalf("Wrong ack number: Expected %v, got %v", packet.ackNumber, packets[k].(*data).ackNumber)
    }
    if packet.dataType != packets[k].(*data).dataType {
      t.Fatalf("Wrong data type: Expected %v, got %v", packet.dataType, packets[k].(*data).dataType)
    }
    if !bytes.Equal(packet.data, packets[k].(*data).data) {
      t.Fatalf("Wrong data: Expected %v, got %v", packet.data, packets[k].(*data).data)
    }
  }
}
