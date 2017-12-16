package dangerous

import (
	"bytes"
	"testing"
)

func TestNewGenericSigner(t *testing.T) {
	key := []byte{116, 101, 115, 116, 105, 110, 103}
	signer := NewGenericSigner("testing")

	genericSigner, ok := signer.(*GenericSigner)
	if !ok {
		t.Errorf("expected *GenericSigner, got %T", signer)
	}

	if !bytes.Equal(genericSigner.key, key) {
		t.Errorf("expected %v, got %v", key, genericSigner.key)
	}
}

func TestGenericSigner_Sign(t *testing.T) {
	key := "testing"
	message := "hello"
	signedMessage := "aGVsbG8=.+JOUrYi7eQZbEMBgqnN8bCkdk5B7zuq5hqZ933+dsak="

	signer := &GenericSigner{key: []byte(key)}

	signedData := signer.Sign(message)

	if signedData != signedMessage {
		t.Errorf("expected %v, got %v", signedMessage, signedData)
	}
}

func TestGenericSigner_Verify(t *testing.T) {
	key := "testing"
	message := "hello"
	signedMessage := "aGVsbG8=.+JOUrYi7eQZbEMBgqnN8bCkdk5B7zuq5hqZ933+dsak="

	signer := &GenericSigner{key: []byte(key)}

	unsignedData, err := signer.Verify(signedMessage)
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	if unsignedData != message {
		t.Errorf("expected %v, got %v", message, unsignedData)
	}
}

func TestGenericSigner_Verify_MessageNotBase64(t *testing.T) {
	key := "testing"
	signedMessage := "aG||VsbG8=.+JOUrYi7eQZbEMBgqnN8bCkdk5B7zuq5hqZ933+dsak="

	signer := &GenericSigner{key: []byte(key)}

	unsignedData, err := signer.Verify(signedMessage)
	if err != ErrInvalidSignature {
		t.Errorf("expected %v, got %v", ErrInvalidSignature, err)
	}

	if unsignedData != "" {
		t.Errorf("expected \"\", got %v", unsignedData)
	}
}

func TestGenericSigner_Verify_TamperedMessage(t *testing.T) {
	key := "testing"
	signedMessage := "aGVsbG93b3JsZA==.+JOUrYi7eQZbEMBgqnN8bCkdk5B7zuq5hqZ933+dsak="

	signer := &GenericSigner{key: []byte(key)}

	unsignedData, err := signer.Verify(signedMessage)
	if err != ErrInvalidSignature {
		t.Errorf("expected %v, got %v", ErrInvalidSignature, err)
	}

	if unsignedData != "" {
		t.Errorf("expected \"\", got %v", unsignedData)
	}
}
