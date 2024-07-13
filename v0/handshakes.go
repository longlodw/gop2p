package v0

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net"
)

type Handshake struct {
  randomSecret []byte
  localPublicKeyED []byte
  localPrivateKeyED []byte
  peerPublicKeyED []byte
  privateKeyDH *ecdh.PrivateKey
  publicKeyDH *ecdh.PublicKey
  router *Router
  udpConn *net.UDPConn
  newConnections chan *Connection
}

func (handShake *Handshake) Connect(addr *net.UDPAddr) error {
  privateKeyDH, err := ecdh.X25519().GenerateKey(rand.Reader)
  if err != nil {
    return err
  }
  publicKeyDH := privateKeyDH.PublicKey()
  newHandshake := &Handshake{
    randomSecret: handShake.randomSecret,
    localPublicKeyED: handShake.localPublicKeyED,
    localPrivateKeyED: handShake.localPrivateKeyED,
    peerPublicKeyED: nil,
    privateKeyDH: privateKeyDH,
    publicKeyDH: publicKeyDH,
    router: handShake.router,
    udpConn: handShake.udpConn,
    newConnections: handShake.newConnections,
  }
  hello := &Hello{
    PublicKeyDH: [PublicKeyDHSize]byte(publicKeyDH.Bytes()),
    PublicKeyED: [PublicKeyEDSize]byte(handShake.localPublicKeyED),
    Signature: [SignatureSize]byte(ed25519.Sign(handShake.localPrivateKeyED, append(publicKeyDH.Bytes(), handShake.localPublicKeyED...))),
    Cookie: [32]byte{},
  }
  transaction := &Transaction[Packet]{Des: &Identifier{Address: addr}, Chunks: []Packet{hello}}
  err = sendTransactionBytes(handShake.udpConn, DefaultPacketSerialize(transaction))
  if err != nil {
    return err
  }
  handShake.router.mutex.Lock()
  handShake.router.ipToHandler[addr.String()] = newHandshake
  handShake.router.mutex.Unlock()
  return nil
}

func (handshake *Handshake) Accept() (*Connection, error) {
  err := handshake.router.ingest(handshake.udpConn)
  if err != nil {
    return nil, err
  }
  return <-handshake.newConnections, nil
}

func (handShake *Handshake) OnPacket(packet Packet, source *Identifier) (PacketsHandler, *Transaction[Packet], error) {
  packageType := packet.Type()
  if packageType == PacketHello {
    return handShake.onHello(packet.(*Hello), source)
  }
  if packageType == PacketHelloRetry {
    return handShake.onHelloRetry(packet.(*HelloRetry), source)
  }
  return nil, nil, errors.New("Invalid packet type expected hello or hello retry")
}

func (handshake *Handshake) Serialize(packets *Transaction[Packet]) *Transaction[[]byte] {
  return DefaultPacketSerialize(packets)
}

func (handshake *Handshake) Deserialize(buf []byte) *Transaction[Packet] {
  packet, _, err := DeserializePacket(buf)
  if err != nil {
    return nil
  }
  return &Transaction[Packet]{Des: nil, Chunks: []Packet{packet}}
}

func (handShake *Handshake) onHello(packet *Hello, source *Identifier) (PacketsHandler, *Transaction[Packet], error) {
  expectedCookie := computeCookie(packet.PublicKeyDH[:], packet.PublicKeyED[:], packet.Signature[:], handShake.randomSecret)
  if bytes.Equal(expectedCookie[:], packet.Cookie[:]) {
    peerPublicKeyDH, err := ecdh.X25519().NewPublicKey(packet.PublicKeyDH[:])
    if err != nil {
      return nil, nil, err
    }
    privateKeyDH, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil {
      return nil, nil, err
    }
    secretAES, err := privateKeyDH.ECDH(peerPublicKeyDH)
    if err != nil {
      return nil, nil, err
    }
    conn := NewConnection(handShake.randomSecret, source.Address, handShake.localPublicKeyED, handShake.localPrivateKeyED, packet.PublicKeyED[:], secretAES, handShake.router, handShake.udpConn)
    return conn, nil, nil
  }
  if !verifyHello(packet.PublicKeyDH[:], packet.PublicKeyED[:], packet.Signature[:]) {
    return nil, nil, errors.New("Invalid signature")
  }
  retryPacket := &HelloRetry{
    Cookie: expectedCookie,
  }
  return nil, &Transaction[Packet]{Des: source, Chunks: []Packet{retryPacket}}, nil
}

func (handshake *Handshake) onHelloRetry(packet *HelloRetry, source *Identifier) (PacketsHandler, *Transaction[Packet], error) {
  publicKeyDHBytes := handshake.publicKeyDH.Bytes()
  hello := &Hello{
    Cookie: packet.Cookie,
    PublicKeyDH: [PublicKeyDHSize]byte(publicKeyDHBytes),
    PublicKeyED: [PublicKeyEDSize]byte(handshake.localPublicKeyED),
    Signature: [SignatureSize]byte(ed25519.Sign(handshake.localPrivateKeyED, append(publicKeyDHBytes, handshake.localPublicKeyED...))),
  }
  return nil, &Transaction[Packet]{Des: source, Chunks: []Packet{hello}}, nil
}

func computeCookie(publicKeyDH []byte, publicKeyED []byte, signature []byte, secret []byte) [32]byte {
  return sha256.Sum256(append(append(append(publicKeyDH, publicKeyED...), signature...), secret...))
}

func verifyHello(publicKeyDH []byte, publicKeyED []byte, signature []byte) bool {
  return ed25519.Verify(publicKeyDH, append(publicKeyDH, publicKeyED...), signature)
}

