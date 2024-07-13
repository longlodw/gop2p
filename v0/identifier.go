package v0

import "net"

type Identifier struct {
  PublicKeyED []byte
  Address *net.UDPAddr
}
