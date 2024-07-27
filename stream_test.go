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
  buffer := make([]*data, 16)
  expectedConsumableBuffer := make([]byte, 0, MaxDataSize)
  for k := 0; k < len(buffer); k += 1 {
    lBytes := [2]byte{}
    rand.Read(lBytes[:])
    l := binary.LittleEndian.Uint16(lBytes[:])
    dataLen := l % MaxDataSize
    dataBuf := make([]byte, dataLen)
    rand.Read(dataBuf)
    buffer[k] = &data{
      streamID: 0,
      dataType: 0,
      sequenceNumber: ackNumber + uint32(k),
      data: dataBuf,
    }
    expectedConsumableBuffer = append(expectedConsumableBuffer, dataBuf...)
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
  transactions := make([]*data, 16)
  for k := 0; k < len(transactions); k += 1 {
    transactions[k] = &data{
      streamID: 0,
      dataType: 0,
      sequenceNumber: uint32(k),
    }
  }
  mrand.Shuffle(len(transactions), func(i, j int) {
    transactions[i], transactions[j] = transactions[j], transactions[i]
  })
  buffer := make([]*data, 0)
  for _, transaction := range transactions {
    buffer = addDataToBuffer(buffer, transaction)
  }
  for _, transaction := range transactions {
    buffer = addDataToBuffer(buffer, transaction)
  }
  for k := 0; k < len(buffer); k += 1 {
    if buffer[k].sequenceNumber != uint32(k) {
      t.Fatalf("Expected %d, got %d", k, buffer[k].sequenceNumber)
    }
  }
  t.Logf("Passed addDataToBuffer")
}

func TestOnData(t *testing.T) {
  stream := newStream(0)
  transactions := make([]*data, 16)
  expectedConsumableBuffer := make([]byte, 0, MaxDataSize)
  for k := 0; k < len(transactions); k += 1 {
    dataLen := mrand.Intn(MaxDataSize)
    dataBuf := make([]byte, dataLen)
    rand.Read(dataBuf)
    transactions[k] = &data{
      streamID: 0,
      dataType: 0,
      sequenceNumber: uint32(k),
      data: dataBuf,
    }
    expectedConsumableBuffer = append(expectedConsumableBuffer, dataBuf...)
  }
  mrand.Shuffle(len(transactions), func(i, j int) {
    transactions[i], transactions[j] = transactions[j], transactions[i]
  })
  consumableBuffer := make([]byte, 0, MaxDataSize)
  for _, transaction := range transactions {
    var (
      closed bool
      packets []packet
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
