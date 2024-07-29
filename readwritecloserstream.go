package gop2p

import (
	"context"
	"io"
	"net"
)

// ReadWriteStream is a stream on a specific address implements io.ReadWriteCloser.
// Before reading or writing, the stream must be opened by either accepting or connecting then open the stream.
type ReadWriteCloserStream struct {
  node *Node
  addr *net.UDPAddr
  streamID byte
}

func NewReadWriteStream(node *Node, addr *net.UDPAddr, streamID byte) *ReadWriteCloserStream {
  return &ReadWriteCloserStream{
    node: node,
    addr: addr,
    streamID: streamID,
  }
}

func (s *ReadWriteCloserStream) Write(data []byte) (int, error) {
  return s.node.Send(data, s.addr, s.streamID)
}

func (s *ReadWriteCloserStream) Read(data []byte) (int, error) {
  n, err := s.node.Recv(context.Background(), data, s.addr, s.streamID)
  if n == 0 && err == nil {
    return 0, io.EOF
  }
  return n, err
}

func (s *ReadWriteCloserStream) Close() error {
  return s.node.CloseStream(s.addr, s.streamID)
}
