package mock

import (
	"testing"

	"github.com/aisola/dangerous"
)

func TestMockSigner_Sign(t *testing.T) {
	signer := &MockSigner{}

	data := signer.Sign("testing")

	if data != "testing" {
		t.Errorf("expected \"testing\", got %v", data)
	}
}

func TestMockSigner_Verify(t *testing.T) {
	signer := &MockSigner{}

	data, err := signer.Verify("testing")
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	if data != "testing" {
		t.Errorf("expected \"testing\", got %v", data)
	}
}

func TestMockSigner_Verify_Error(t *testing.T) {
	signer := &MockSigner{VerifyFail: true}

	data, err := signer.Verify("testing")
	if err != dangerous.ErrInvalidSignature {
		t.Errorf("expected %v, got %v", dangerous.ErrInvalidSignature, err)
	}

	if data != "" {
		t.Errorf("expected \"\", got %v", data)
	}
}
