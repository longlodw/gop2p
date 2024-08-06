package gop2p

import (
	"fmt"
)

type PeerConnectionNotEstablishedError struct {
  addr string
}

func (e PeerConnectionNotEstablishedError) Error() string {
  return fmt.Sprintf("Connection to peer %s not established", e.addr)
}

func newPeerConnectionNotEstablishedError(addr string) PeerConnectionNotEstablishedError {
  return PeerConnectionNotEstablishedError{addr: addr}
}

type PeerConnectionAlreadyEstablishedError struct {
  addr string
}

func (e PeerConnectionAlreadyEstablishedError) Error() string {
  return fmt.Sprintf("Connection to peer %s already established", e.addr)
}

func newConnectionAlreadyEstablishedError(addr string) PeerConnectionAlreadyEstablishedError {
  return PeerConnectionAlreadyEstablishedError{addr: addr}
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

type StreamNotEstablishedError struct {
  streamID byte
}

func (e StreamNotEstablishedError) Error() string {
  return fmt.Sprintf("Stream %d not found", e.streamID)
}

func newStreamNotEstablishedError(streamID byte) StreamNotEstablishedError {
  return StreamNotEstablishedError{streamID: streamID}
}

type StreamAlreadyEstablishedError struct {
  streamID byte
}

func (e StreamAlreadyEstablishedError) Error() string {
  return fmt.Sprintf("Stream %d already opened", e.streamID)
}

func newStreamAlreadyEstablishedError(streamID byte) StreamAlreadyEstablishedError {
  return StreamAlreadyEstablishedError{streamID: streamID}
}
