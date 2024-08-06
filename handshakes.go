package gop2p

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net"
)

type handshake struct {
  privateKeyDH *ecdh.PrivateKey
  publicKeyDH *ecdh.PublicKey
  maxStreamQueue int
}

func newHandshake(maxStreamQueue int) *handshake {
  privateKeyDH, err := ecdh.X25519().GenerateKey(rand.Reader)
  if err != nil {
    return nil
  }
  publicKeyDH := privateKeyDH.PublicKey()
  return &handshake{
    privateKeyDH: privateKeyDH,
    publicKeyDH: publicKeyDH,
    maxStreamQueue: maxStreamQueue,
  }
}

func (hs *handshake) onHello(packet *hello, source *net.UDPAddr) (*peerConnection, error) {
  if !verifyHello(packet.publicKeyDH[:], packet.publicKeyED[:], packet.signature[:]) {
    return nil, newInvalidPacketError("Invalid signature")
  }
  publicKeyDH, err := ecdh.X25519().NewPublicKey(packet.publicKeyDH[:])
  if err != nil {
    return nil ,err
  }
  aesSecret, err := hs.privateKeyDH.ECDH(publicKeyDH)
  if err != nil {
    return nil, err
  }
  return newPeerConnection(source, packet.publicKeyED[:], aesSecret, hs.maxStreamQueue), nil
}

func (hs *handshake) onHelloRetry(packet *helloRetry, source *net.UDPAddr, udpConn *net.UDPConn, localPrivateKeyED []byte, localPublicKeyED []byte) error {
  publicKeyDHBytes := hs.publicKeyDH.Bytes()
  hello := &hello{
    cookie: packet.cookie,
    publicKeyDH: [PublicKeyDHSize]byte(publicKeyDHBytes),
    publicKeyED: [PublicKeyEDSize]byte(localPublicKeyED),
    signature: [SignatureSize]byte(ed25519.Sign(localPrivateKeyED, append(publicKeyDHBytes, localPublicKeyED...))),
  }
  buf := make([]byte, hello.BufferSize())
  n, err := hello.Serialize(buf)
  if err != nil {
    return err
  }
  _, err = udpConn.WriteToUDP(buf[:n], source)
  return err
}

func computeCookie(publicKeyDH []byte, publicKeyED []byte, signature []byte, secret []byte) [32]byte {
  return sha256.Sum256(append(append(append(publicKeyDH, publicKeyED...), signature...), secret...))
}

func verifyHello(publicKeyDH []byte, publicKeyED []byte, signature []byte) bool {
  return ed25519.Verify(publicKeyED, append(publicKeyDH, publicKeyED...), signature)
}

