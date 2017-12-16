package dangerous

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// Signer is the interface to which all signers must conform.
type Signer interface {
	Sign(string) string
	Verify(string) (string, error)
}

// GenericSigner is the first and simple signer that is sufficient for simple applications. This signer
// takes a key of sufficient length. It will generate the signature based on HMAC+SHA256.
type GenericSigner struct {
	key []byte
}

// NewGenericSigner creates a new standard signer with the given key.
func NewGenericSigner(key string) Signer {
	return &GenericSigner{key: []byte(key)}
}

func (gs *GenericSigner) b64Encode(message []byte) string {
	return base64.StdEncoding.EncodeToString(message)
}

func (gs *GenericSigner) b64Decode(message string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(message)
}

func (gs *GenericSigner) computeSignature(message string) []byte {
	h := hmac.New(sha256.New, gs.key)
	h.Write([]byte(message))
	return h.Sum(nil)
}

// Sign will compute the HMAC-SHA256 signature of the given message. The message and signature are then individually
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
