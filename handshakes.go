package gop2p

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net"
)

type Handshake struct {
  privateKeyDH *ecdh.PrivateKey
  publicKeyDH *ecdh.PublicKey
}

func NewHandshake() *Handshake {
  privateKeyDH, err := ecdh.X25519().GenerateKey(rand.Reader)
  if err != nil {
    return nil
  }
  publicKeyDH := privateKeyDH.PublicKey()
  return &Handshake{
    privateKeyDH: privateKeyDH,
    publicKeyDH: publicKeyDH,
  }
}

func (handShake *Handshake) onHello(packet *Hello, source *net.UDPAddr) (*EncryptedConnection, error) {
  if !verifyHello(packet.PublicKeyDH[:], packet.PublicKeyED[:], packet.Signature[:]) {
    return nil, newInvalidPacketError("Invalid signature")
  }
  publicKeyDH, err := ecdh.X25519().NewPublicKey(packet.PublicKeyDH[:])
  if err != nil {
    return nil ,err
  }
  aesSecret, err := handShake.privateKeyDH.ECDH(publicKeyDH)
  if err != nil {
    return nil, err
  }
  return NewEncryptedConnection(source, packet.PublicKeyED[:], aesSecret), nil
}

func (handshake *Handshake) onHelloRetry(packet *HelloRetry, source *net.UDPAddr, udpConn *net.UDPConn, localPrivateKeyED []byte, localPublicKeyED []byte) error {
  publicKeyDHBytes := handshake.publicKeyDH.Bytes()
  hello := &Hello{
    Cookie: packet.Cookie,
    PublicKeyDH: [PublicKeyDHSize]byte(publicKeyDHBytes),
    PublicKeyED: [PublicKeyEDSize]byte(localPublicKeyED),
    Signature: [SignatureSize]byte(ed25519.Sign(localPrivateKeyED, append(publicKeyDHBytes, localPublicKeyED...))),
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

