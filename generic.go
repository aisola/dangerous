package dangerous

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
)

// Signer is the interface to which all signers must conform.
type Signer interface {
	Sign(string) string
	Verify(string) (string, error)
}

// GenericSigner is the first and simple signer that is sufficient for simple applications. This signer
// takes a key of sufficient length. It will generate the signature using HMAC and a which ever hash function is chosen
// on creation.
type GenericSigner struct {
	key      []byte
	hashFunc func() hash.Hash
}

// NewGenericSigner creates a new Signer with the given key using the SHA1 hash function.
func NewGenericSigner(key string) Signer {
	return NewSHA1Signer(key)
}

// NewMD5Signer creates a new Signer with the given key using the MD5 hash function.
func NewMD5Signer(key string) Signer {
	return newSigner(key, md5.New)
}

// NewSHA1Signer creates a new Signer with the given key using the SHA1 hash function.
func NewSHA1Signer(key string) Signer {
	return newSigner(key, sha1.New)
}

// NewSHA256Signer creates a new Signer with the given key using the SHA256 hash function.
func NewSHA256Signer(key string) Signer {
	return newSigner(key, sha256.New)
}

// NewSHA512Signer creates a new Signer with the given key using the SHA512 hash function.
func NewSHA512Signer(key string) Signer {
	return newSigner(key, sha512.New)
}

func newSigner(key string, hashFunc func() hash.Hash) Signer {
	return &GenericSigner{
		key:      []byte(key),
		hashFunc: hashFunc,
	}
}

func (gs *GenericSigner) b64Encode(message []byte) string {
	return base64.StdEncoding.EncodeToString(message)
}

func (gs *GenericSigner) b64Decode(message string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(message)
}

func (gs *GenericSigner) computeSignature(message string) []byte {
	h := hmac.New(gs.hashFunc, gs.key)
	h.Write([]byte(message))
	return h.Sum(nil)
}

// Sign will compute the HMAC-SHA1 signature of the given message. The message and signature are then individually
// base64 encoded and concatenated by a period.
func (gs *GenericSigner) Sign(message string) string {
	signature := gs.computeSignature(message)
	return fmt.Sprintf("%s.%s", gs.b64Encode([]byte(message)), gs.b64Encode(signature))
}

// Verify will return the data of the validated payload or an error.
func (gs *GenericSigner) Verify(payload string) (string, error) {
	dataParts := strings.Split(payload, ".")
	message := dataParts[0]
	signature := dataParts[1]

	messageData, err := gs.b64Decode(message)
	if err != nil {
		return "", ErrInvalidSignature
	}

	messageSignature := gs.computeSignature(string(messageData))

	if signature == gs.b64Encode(messageSignature) {
		return string(messageData), nil
	}

	return "", ErrInvalidSignature
}
