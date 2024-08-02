package gop2p

import (
	"context"
	"io"
	"net"
	"time"
)

// ReadWriteStream is a stream on a specific address implements io.ReadWriteCloser.
// Before reading or writing, the stream must be opened by either accepting or connecting then open the stream.
type ReadWriteCloserStream struct {
  node *Node
  addr *net.UDPAddr
  streamID byte
  timeout time.Duration
}

func NewReadWriteStream(node *Node, addr *net.UDPAddr, streamID byte, timeout time.Duration) *ReadWriteCloserStream {
  return &ReadWriteCloserStream{
    node: node,
    addr: addr,
    streamID: streamID,
    timeout: timeout,
  }
}

func (s *ReadWriteCloserStream) Write(data []byte) (int, error) {
  ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
  defer cancel()
  return s.node.Send(ctx, data, s.addr, s.streamID)
}

func (s *ReadWriteCloserStream) Read(data []byte) (int, error) {
  ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
  defer cancel()
  n, err := s.node.Recv(ctx, data, s.addr, s.streamID)
  if n == 0 && err == nil {
    return 0, io.EOF
  }
  return n, err
}

func (s *ReadWriteCloserStream) Close() error {
  return s.node.CloseStream(s.addr, s.streamID)
}
