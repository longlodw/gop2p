package v0

import (
	"net"
	"sync"
)

type Router struct {
  ipToHandler map[string]PacketsHandler
  mutex sync.RWMutex
}

func NewRouter() *Router {
  return &Router{
    ipToHandler: make(map[string]PacketsHandler),
  }
}

func (router *Router) getPeerList() []Identifier {
  router.mutex.RLock()
  defer router.mutex.RUnlock()
  peers := make([]Identifier, 0)
  for ip, ph := range router.ipToHandler {
    addr, err := net.ResolveUDPAddr("udp6", ip)
    if err != nil {
      continue
    }
    if conn, ok := ph.(*Connection); ok {
      peers = append(peers, Identifier{Address: addr, PublicKeyED: conn.peerPublicKeyED})
    } else {
      peers = append(peers, Identifier{Address: addr})
    }
  }
  return peers
}

func (router *Router) ingest(udpConn *net.UDPConn) error {
  buf := make([]byte, MaxPacketSize)
  n, addr, err := udpConn.ReadFromUDP(buf)
  if err != nil {
    return err
  }
  ph, ok := router.ipToHandler[addr.String()]
  if !ok {
    ph = router.ipToHandler[""]
  }
  newPh, transactionsBytes, err := HandleBytes(ph, buf[:n], addr, router.ipToHandler[""].(*Handshake).newConnections)
  if err != nil {
    return err
  }
  if newPh != nil {
    router.mutex.Lock()
    router.ipToHandler[addr.String()] = newPh
    router.mutex.Unlock()
  }
  if transactionsBytes != nil {
    err = sendTransactionBytes(udpConn, transactionsBytes)
    if err != nil {
      return err
    }
  }
  return nil
}

