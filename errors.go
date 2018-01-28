package dangerous

import (
	"errors"
)

var (
	ErrInvalidFormat = errors.New("invalid format")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	ErrExpired = errors.New("expired")
)
