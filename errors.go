package gop2p

import (
	"fmt"
)

type ConnectionNotEstablishedError struct {
  addr string
}

func (e ConnectionNotEstablishedError) Error() string {
  return fmt.Sprintf("Connection to %s not established", e.addr)
}

func newConnectionNotEstablishedError(addr string) ConnectionNotEstablishedError {
  return ConnectionNotEstablishedError{addr: addr}
}

type ConnectionAlreadyEstablishedError struct {
  addr string
}

func (e ConnectionAlreadyEstablishedError) Error() string {
  return fmt.Sprintf("Connection to %s already established", e.addr)
}

func newConnectionAlreadyEstablishedError(addr string) ConnectionAlreadyEstablishedError {
  return ConnectionAlreadyEstablishedError{addr: addr}
}

type CancelledError struct {}

func (e CancelledError) Error() string {
  return "Operation cancelled"
}

func newCancelledError() CancelledError {
  return CancelledError{}
}

type ChannelClosedError struct {}

func (e ChannelClosedError) Error() string {
  return "Channel closed"
}

func newChannelClosedError() ChannelClosedError {
  return ChannelClosedError{}
}

type InvalidPacketError struct {
  reason string
}

func (e InvalidPacketError) Error() string {
  if e.reason != "" {
    return fmt.Sprintf("Invalid packet: %s", e.reason)
  }
  return "Invalid packet"
}

func newInvalidPacketError(reason string) InvalidPacketError {
  return InvalidPacketError{
    reason: reason,
  }
}

type StreamNotFoundError struct {
  streamID byte
}

func (e StreamNotFoundError) Error() string {
  return fmt.Sprintf("Stream %d not found", e.streamID)
}

func newStreamNotFoundError(streamID byte) StreamNotFoundError {
  return StreamNotFoundError{streamID: streamID}
}



