package gop2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
  node, err := NewNode(pvk1, pbk1, addr, 16, 16)
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
    err := node1.ConnectPeer(context.TODO(), addr2)
    if err != nil {
      errChan <- err
      return
    }
    defer node1.ClosePeer(addr2)
    err = node1.ConnectStream(addr2, 0)
    if err != nil {
      errChan <- err
      return
    }
    n, err := node1.Send(context.TODO(), bytesToSend, addr2, 0)
    if err != nil {
      errChan <- err
      return
    }
    if n != len(bytesToSend) {
      errChan <- errors.New(fmt.Sprintf("Failed to send all bytes got %d expected %d", n, len(bytesToSend)))
      return
    }
    select {
    case doneChan <- struct{}{}:
      return
    case err := <-errChan:
      errChan <- err
      return
    }
  }()

  addr, err := node2.AcceptPeer(context.TODO())
  if err != nil {
    t.Fatal(err)
  }
  _, err = node2.AcceptStream(context.TODO(), addr)
  if err != nil {
    t.Fatal(err)
  }
  recvBuf := make([]byte, 2048)
  l := 0
  n := -1
  for n != 0 {
    select {
    case err := <-errChan:
      t.Fatal(err)
    default:
      n, err = node2.Recv(context.TODO(), recvBuf[l:], addr, 0)
      if err != nil {
	t.Fatal(err)
      }
      l += n
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
}

func TestConnectViaPeer(t *testing.T) {
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
    err := node3.ConnectPeer(context.TODO(), addr1)
    if err != nil {
      errChan <- err
      return
    }
    _, err = node3.AcceptPeer(context.TODO())
    if err != nil {
      errChan <- err
      return
    }
    doneChan <- struct{}{}
  }()
  go func() {
    err := node2.ConnectPeer(context.TODO(), addr1)
    if err != nil {
      errChan <- err
      return
    }
    err = node2.ConnectPeerViaPeer(context.TODO(), addr3, addr1)
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
      _, err := node1.AcceptPeer(context.TODO())
      if err != nil {
	t.Fatal(err)
      }
    }
  }
  select {
  case err := <-errChan:
    t.Fatal(err)
  case <-doneChan:
    break
  }
}
