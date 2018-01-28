package dangerous

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"hash"
	"time"
	"strconv"
	"strings"
)

// Dangerous is the all-in-one signature mechanism.
type Dangerous struct {
	key []byte

	// Base64, when true, will make dangerous automatically Base64 encode the
	// end result.
	Base64 bool

	// Duration specifies the amount of time after signing a signature will be
	// valid. If duration is 0, then the signature will never expire.
	Duration time.Duration

	// Hash is the hashing mechanism used. By default, this will be sha1.New
	// from the standard library's crypto/sha1.
	Hash func() hash.Hash
}

// New creates a new Dangerous instance from a key with a SHA1 hash.
func New(key string) *Dangerous {
	return &Dangerous{
		key:      []byte(key),
		Hash:     sha1.New,
		Duration: 0,
		Base64:   true,
	}
}

func (d *Dangerous) computeSignature(message string) []byte {
	h := hmac.New(d.Hash, d.key)
	h.Write([]byte(message))
	return h.Sum(nil)
}

// Sign the message. If the dangerous instance has a non-zero duration, a
// timestamp will be added in order to set the expiration of the message. If
// the dangerous instance has Base64=true, then the final result will be base64
// encoded. Ultimately, the format of the result is <message>.<signature> or
// <message>.<timestamp>.<signature> which may be base64 encoded.
func (d *Dangerous) Sign(message string) string {
	if d.Duration != 0 {
		expires := time.Now().Add(d.Duration).Unix()
		message = fmt.Sprintf("%s.%d", message, expires)
	}

	signature := d.computeSignature(message)
	out := fmt.Sprintf("%s.%s", message, string(signature))

	if d.Base64 {
		out = base64.StdEncoding.EncodeToString([]byte(out))
	}

	return out
}

// Verify the signature is valid. First it will decode the entire payload from
// base64 if necessary. Then Verify will split the signature from the message
// payload and verify the signature. If there are format errors, verify will
// return ErrInvalidFormat, if the signature is invalid (data has been tampered
// with) then ErrInvalidSignature is returned. Additionally, if the dangerous
// instance defines a duration, then the timestamp will be checked. If the
// timestamp is invalid, ErrInvalidTimestamp is returned, if the timestamp
// is in the past, then ErrExpired is returned. If all goes well, then the
// verified message is returned.
func (d *Dangerous) Verify(payload string) (string, error) {
	if d.Base64 {
		payloadByte, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return "", err
		}
		payload = string(payloadByte)
	}

	parts := strings.Split(payload, ".")
	if len(parts) < 2 {
		return "", ErrInvalidFormat
	}

	signature := []byte(parts[len(parts) - 1])
	message := strings.Join(parts[:len(parts) - 1], ".")

	messageSignature := d.computeSignature(message)

	if !bytes.Equal(signature, messageSignature) {
		return "", ErrInvalidSignature
	}

	if d.Duration != 0 {
		messageParts := strings.Split(message, ".")
		if len(messageParts) < 2 {
			return "", ErrInvalidFormat
		}

		timestamp := messageParts[len(messageParts) - 1]
		message = strings.Join(messageParts[:len(messageParts) - 1], ".")

		i, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			return "", ErrInvalidTimestamp
		}
		expires := time.Unix(i, 0)

		if !expires.After(time.Now()) {
			return "", ErrExpired
		}
	}

	return message, nil
}
