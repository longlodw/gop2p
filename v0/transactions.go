package v0

import "net"

type Transaction[T any] struct {
  Des *Identifier
  Chunks []T
}

func sendTransactionBytes(udpConn *net.UDPConn, transaction *Transaction[[]byte]) error {
  for _, ch := range transaction.Chunks {
    _, err := udpConn.WriteToUDP(ch, transaction.Des.Address)
    if err != nil {
      return err
    }
  }
  return nil
}
