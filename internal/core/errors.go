package core

import "errors"

var (
	ErrKeyNotFound      = errors.New("key not found")
	ErrKeyExists        = errors.New("key already exists")
	ErrInvalidEnvelope  = errors.New("invalid envelope")
	ErrInvalidSignature = errors.New("invalid signature")
)
