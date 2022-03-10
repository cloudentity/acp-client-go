package acpclient

import (
	"encoding/json"
	"io"

	"github.com/dgrijalva/jwt-go"
)

var parser jwt.Parser

type JWTConsumer struct{}

type JWTClaims map[string]interface{}

func (j *JWTClaims) Valid() error {
	return nil
}

func (c *JWTConsumer) Consume(r io.Reader, out interface{}) error {
	var (
		claims    JWTClaims
		body      []byte
		marshaled []byte
		err       error
	)

	if body, err = io.ReadAll(r); err != nil {
		return err
	}

	if _, _, err = parser.ParseUnverified(string(body), &claims); err != nil {
		return err
	}

	if marshaled, err = json.Marshal(claims); err != nil {
		return err
	}

	return json.Unmarshal(marshaled, out)
}
