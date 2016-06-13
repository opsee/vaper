package vaper

import (
	"fmt"
	"reflect"
	"time"
)

var (
	ErrorTokenExpired = fmt.Errorf("token expired")
	ErrorTokenInvalid = fmt.Errorf("token invalid")
	vapeKey           []byte
	cryptOpts         *CryptOpts
)

func Init(sharedKey []byte) {
	vapeKey = sharedKey
	cryptOpts = &CryptOpts{
		DefaultAlgorithm,
		DefaultEncryption,
		vapeKey,
	}
}

type TokenValidator interface {
	Expired() error
}

type Token struct {
	Thing interface{} `token:"thing"`
	Exp   time.Time   `token:"exp"`
	Iat   time.Time   `token:"iat"`
	Sub   string      `token:"sub"`
}

func (t *Token) Marshal() (string, error) {
	b, err := MarshalToken(t, cryptOpts)
	return string(b), err
}

func (t *Token) Expired() error {
	now := time.Now().UTC()
	if now.Before(t.Exp) != true {
		return ErrorTokenExpired
	}

	if t.Iat.Before(now) != true {
		return ErrorTokenInvalid
	}
	return nil
}

func (token *Token) Reify(thing interface{}) error {
	v := reflectValue(thing)
	vv := reflectValue(token.Thing)

	if v.CanSet() && reflect.TypeOf(thing) == reflect.TypeOf(token.Thing) {
		v.Set(vv)
	} else {
		return fmt.Errorf("thing is of type %T, expected %T", reflect.TypeOf(thing), reflect.TypeOf(token.Thing))
	}
	return nil
}

func reflectValue(obj interface{}) reflect.Value {
	var val reflect.Value

	if reflect.TypeOf(obj).Kind() == reflect.Ptr {
		val = reflect.ValueOf(obj).Elem()
	} else {
		val = reflect.ValueOf(obj)
	}

	return val
}

// Legacy
func Unmarshal(tokenString string) (*Token, error) {
	token := &Token{}
	err := UnmarshalToken([]byte(tokenString), token, cryptOpts)
	if err != nil {
		return nil, err
	}

	if err = token.Expired(); err != nil {
		return nil, err
	}

	return token, nil
}

func New(thing interface{}, sub string, iat, exp time.Time) *Token {
	return &Token{
		Thing: thing,
		Sub:   sub,
		Iat:   iat,
		Exp:   exp,
	}
}
