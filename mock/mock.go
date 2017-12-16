package mock

import (
	"github.com/aisola/dangerous"
)

// MockSigner is a valid signer that is mainly used for testing purposes.
type MockSigner struct {
	VerifyFail bool
}

// Sign simple returns the string passed to it.
func (ms *MockSigner) Sign(message string) string {
	return message
}

// Verify will return the payload as given unless MockSigner.VerifyFail is true, then it will
// return an empty string and dangerous.ErrInvalidSignature.
func (ms *MockSigner) Verify(payload string) (string, error) {
	if ms.VerifyFail {
		return "", dangerous.ErrInvalidSignature
	}
	return payload, nil
}
