package gop2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
)

func makeTestNode(port int) (*Node, *net.UDPAddr) {
  addr := &net.UDPAddr{IP: net.IPv6loopback, Port: port}
  pbk1, pvk1, err := ed25519.GenerateKey(rand.Reader)
  if err != nil {
    return nil, nil
  }
  node, err := NewNode(pvk1, pbk1, addr)
  if err != nil {
    return nil, nil
  }
  return node, addr
}

func TestSendRecv(t *testing.T) {
  p1 := 1234
  p2 := 1235
  node1, addr1 := makeTestNode(p1)
  if node1 == nil || addr1 == nil {
    t.Fatal("Failed to create node1")
  }
  defer node1.Shutdown()
  node2, addr2 := makeTestNode(p2)
  if node2 == nil || addr2 == nil {
    t.Fatal("Failed to create node2")
  }
  defer node2.Shutdown()

  bytesToSend := make([]byte, 2048)
  rand.Read(bytesToSend)
  errChan := make(chan error)
  doneChan := make(chan struct{})
  defer close(errChan)
  defer close(doneChan)
  
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
    doneChan <- struct{}{}
  }()

  addr, err := node2.Accept(context.TODO())
  if err != nil {
    t.Fatal(err)
  }
  recvBuf := make([]byte, 0, 2048)
  var b []byte = nil
  for b == nil || len(b) > 0 {
    select {
    case err := <-errChan:
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
  case <-doneChan:
    break
  }
  fmt.Println("passed TestSendRecv")
}

func testConnectViaPeer(t *testing.T) {
  fmt.Println("TestConnectViaPeer")
  p1 := 1234
  p2 := 1235
  p3 := 1236
  node1, addr1 := makeTestNode(p1)
  if node1 == nil || addr1 == nil {
    t.Fatal("Failed to create node1")
  }
  defer node1.Shutdown()
  node2, addr2 := makeTestNode(p2)
  if node2 == nil || addr2 == nil {
    t.Fatal("Failed to create node2")
  }
  defer node2.Shutdown()
  node3, addr3 := makeTestNode(p3)
  if node3 == nil || addr3 == nil {
    t.Fatal("Failed to create node3")
  }
  defer node3.Shutdown()
  errChan := make(chan error)
  doneChan := make(chan struct{})
  defer close(errChan)
  defer close(doneChan)

  go func() {
    err := node3.Connect(context.TODO(), addr1)
    if err != nil {
      errChan <- err
      return
    }
    fmt.Println("node3 connected to node1")
    _, err = node3.Accept(context.TODO())
    fmt.Println("node3 accepted connection from node2")
    if err != nil {
      errChan <- err
      return
    }
    doneChan <- struct{}{}
  }()
  go func() {
    err := node2.Connect(context.TODO(), addr1)
    if err != nil {
      errChan <- err
      return
    }
    fmt.Println("node2 connected to node1")
    err = node2.ConnectViaPeer(context.TODO(), addr3, addr1)
    fmt.Println("node2 connected to node3 via node1")
    if err != nil {
      errChan <- err
      return
    }
  }()
  
  for k := 0; k < 2; k++ {
    fmt.Printf("k = %d\n", k)
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
  fmt.Println("node1 accepted connections from node2 and node3")
  select {
  case err := <-errChan:
    t.Fatal(err)
  case <-doneChan:
    break
  }
}
