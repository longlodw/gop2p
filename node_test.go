package gop2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
)

func makeTestNode(port int) (*Node, *net.UDPConn, *net.UDPAddr) {
  addr := &net.UDPAddr{IP: net.IPv6loopback, Port: port}
  udpConn, err := net.ListenUDP("udp6", addr)
  if err != nil {
    return nil, nil, nil
  }
  pbk1, pvk1, err := ed25519.GenerateKey(rand.Reader)
  if err != nil {
    udpConn.Close()
    return nil, nil, nil
  }
  return NewNode(pvk1, pbk1, udpConn), udpConn, addr
}

func TestSendRecv(t *testing.T) {
  p1 := 1234
  p2 := 1235
  node1, udpConn1, addr1 := makeTestNode(p1)
  if node1 == nil || udpConn1 == nil || addr1 == nil {
    t.Fatal("Failed to create node1")
  }
  node2, udpConn2, addr2 := makeTestNode(p2)
  if node2 == nil || udpConn2 == nil || addr2 == nil {
    t.Fatal("Failed to create node2")
  }

  bytesToSend := make([]byte, 2048)
  rand.Read(bytesToSend)
  stopChan := make(chan struct{})
  errChan := make(chan error)
  defer close(stopChan)
  defer close(errChan)
  
  go func() {
    err := node1.Connect(context.TODO(), addr2)
    if err != nil {
      errChan <- err
      return
    }
    err = node1.Send(bytesToSend, addr2, 0)
    if err != nil {
      errChan <- err
      return
    }
    for {
      select {
      case <- stopChan:
	return
      default:
	err := node1.Run()
	if err != nil {
	  errChan <- err
	  return
	}
      }
    }
  }()

  addr, err := node2.Accept(context.TODO())
  if err != nil {
    stopChan <- struct{}{}
    t.Fatal(err)
  }
  recvBuf := make([]byte, 0, 2048)
  var b []byte = nil
  for b == nil || len(b) > 0 {
    select {
    case err := <-errChan:
      stopChan <- struct{}{}
      t.Fatal(err)
    default:
      var (
	s byte
	err error
      )
      b, s, err = node2.Recv(context.TODO(), addr)
      if err != nil {
	t.Fatal(err)
      }
      if addr.String() != addr1.String() {
	t.Fatalf("Expected %s, got %s", addr1.String(), addr.String())
      }
      if s != 0 {
	t.Fatalf("Expected 0, got %d", s)
      }
      recvBuf = append(recvBuf, b...)
    }
  }
  if !bytes.Equal(recvBuf, bytesToSend) {
    t.Fatalf("Expected %v, got %v", bytesToSend, recvBuf)
  }

  node2.ClosePeer(addr1)
  select {
  case err := <-errChan:
    t.Fatal(err)
  case stopChan <- struct{}{}:
  }
  udpConn1.Close()
  udpConn2.Close()
}

func TestConnectViaPeer(t *testing.T) {
  p1 := 1234
  p2 := 1235
  p3 := 1236
  node1, udpConn1, addr1 := makeTestNode(p1)
  if node1 == nil || udpConn1 == nil || addr1 == nil {
    t.Fatal("Failed to create node1")
  }
  node2, udpConn2, addr2 := makeTestNode(p2)
  if node2 == nil || udpConn2 == nil || addr2 == nil {
    t.Fatal("Failed to create node2")
  }
  node3, udpConn3, addr3 := makeTestNode(p3)
  if node3 == nil || udpConn3 == nil || addr3 == nil {
    t.Fatal("Failed to create node3")
  }
  stopChan := make(chan struct{})
  errChan := make(chan error)
  defer close(stopChan)
  defer close(errChan)

  go func() {
    err := node3.Connect(context.TODO(), addr1)
    if err != nil {
      errChan <- err
      return
    }
    _, err = node3.Accept(context.TODO())
    if err != nil {
      errChan <- err
      return
    }
    stopChan <- struct{}{}
  }()
  go func() {
    err := node2.Connect(context.TODO(), addr1)
    if err != nil {
      errChan <- err
      return
    }
    err = node2.ConnectViaPeer(context.TODO(), addr3, addr1)
    if err != nil {
      errChan <- err
      return
    }
  }()
  
  for k := 0; k < 2; k++ {
    select {
    case err := <-errChan:
      t.Fatal(err)
    default:
      _, err := node1.Accept(context.TODO())
      if err != nil {
	t.Fatal(err)
      }
    }
  }
  err := node1.Run()
  if err != nil {
    t.Fatal(err)
  }
  select {
  case err := <-errChan:
    t.Fatal(err)
  case <-stopChan:
    return
  }
}
