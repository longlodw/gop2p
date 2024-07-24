package gop2p

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"testing"
)

func TestUpdateRxBufferConsumableAckNumber(t *testing.T) {
  ackNumberBytes := [4]byte{}
  rand.Read(ackNumberBytes[:])
  ackNumber := binary.LittleEndian.Uint32(ackNumberBytes[:])
  buffer := make([]*Data, 16)
  expectedConsumableBuffer := make([]byte, 0, MaxDataSize)
  for k := 0; k < len(buffer); k += 1 {
    lBytes := [2]byte{}
    rand.Read(lBytes[:])
    l := binary.LittleEndian.Uint16(lBytes[:])
    dataLen := l % MaxDataSize
    data := make([]byte, dataLen)
    rand.Read(data)
    buffer[k] = &Data{
      StreamID: 0,
      DataType: 0,
      SequenceNumber: ackNumber + uint32(k),
      Data: data,
    }
    expectedConsumableBuffer = append(expectedConsumableBuffer, data...)
  }
  expectedAckNumber := ackNumber + uint32(len(buffer))
  updatedBuffer, consumableBuffer, updatedAckNumber := updateRxBufferConsumableAckNumber(buffer, nil, ackNumber)
  if updatedAckNumber != expectedAckNumber {
    t.Fatalf("Expected %d, got %d", expectedAckNumber, updatedAckNumber)
  }
  if !bytes.Equal(consumableBuffer, expectedConsumableBuffer) {
    t.Fatalf("Expected %v, got %v", expectedConsumableBuffer, consumableBuffer)
  }
  if len(updatedBuffer) != 0 {
    t.Fatalf("Expected 0, got %d", len(updatedBuffer))
  }
  t.Logf("Passed updateRxBufferConsumableAckNumber")
}

func TestAddDataToBuffer(t *testing.T) {
  transactions := make([]*Data, 16)
  for k := 0; k < len(transactions); k += 1 {
    transactions[k] = &Data{
      StreamID: 0,
      DataType: 0,
      SequenceNumber: uint32(k),
    }
  }
  mrand.Shuffle(len(transactions), func(i, j int) {
    transactions[i], transactions[j] = transactions[j], transactions[i]
  })
  buffer := make([]*Data, 0)
  for _, transaction := range transactions {
    buffer = addDataToBuffer(buffer, transaction)
  }
  for _, transaction := range transactions {
    buffer = addDataToBuffer(buffer, transaction)
  }
  for k := 0; k < len(buffer); k += 1 {
    if buffer[k].SequenceNumber != uint32(k) {
      t.Fatalf("Expected %d, got %d", k, buffer[k].SequenceNumber)
    }
  }
  t.Logf("Passed addDataToBuffer")
}

func TestOnData(t *testing.T) {
  stream := newStream(0)
  transactions := make([]*Data, 16)
  expectedConsumableBuffer := make([]byte, 0, MaxDataSize)
  for k := 0; k < len(transactions); k += 1 {
    dataLen := mrand.Intn(MaxDataSize)
    data := make([]byte, dataLen)
    rand.Read(data)
    transactions[k] = &Data{
      StreamID: 0,
      DataType: 0,
      SequenceNumber: uint32(k),
      Data: data,
    }
    expectedConsumableBuffer = append(expectedConsumableBuffer, data...)
  }
  mrand.Shuffle(len(transactions), func(i, j int) {
    transactions[i], transactions[j] = transactions[j], transactions[i]
  })
  consumableBuffer := make([]byte, 0, MaxDataSize)
  for _, transaction := range transactions {
    var (
      closed bool
      packets []Packet
    )
    closed, packets, consumableBuffer = stream.onData(transaction, consumableBuffer)
    if closed {
      t.Fatalf("Expected false, got true")
    }
    if packets != nil {
      t.Fatalf("Expected 0, got %d", len(packets))
    }
  }
  if !bytes.Equal(consumableBuffer, expectedConsumableBuffer) {
    t.Fatalf("Expected %v, got %v", expectedConsumableBuffer, consumableBuffer)
  }
  t.Logf("Passed onData")
}
