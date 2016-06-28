package vaper

import (
	"fmt"
	"reflect"
	"time"

	log "github.com/sirupsen/logrus"
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
	Data interface{} `token:"data"`
	Exp  time.Time   `token:"exp"`
	Iat  time.Time   `token:"iat"`
	Sub  string      `token:"sub"`
}

func (t *Token) decodeTime(k string, v interface{}) error {
	var tt time.Time
	var err error
	switch ts := v.(type) {
	case time.Time:
		tt = ts
	case string:
		tt, err = time.Parse(time.RFC3339, ts)
	case float64:
		tt = time.Unix(int64(ts), 0)
	default:
		err = fmt.Errorf("invalid value %v for key \"time\"", ts)
	}
	switch k {
	case "iat":
		t.Iat = tt
	case "exp":
		t.Exp = tt
	}
	return err
}

func (t *Token) decode(k string, v interface{}) error {
	log.Debugf("decoding %s, %T", k, v)
	switch k {
	case "iat", "exp":
		return t.decodeTime(k, v)
	case "sub":
		if kv, ok := v.(string); ok {
			t.Sub = kv
		} else {
			return fmt.Errorf("invalid value %v for key \"sub\"", kv)
		}
	case "data":
		t.Data = v
	default:
		return fmt.Errorf("encountered unknown field")
	}
	return nil
}

func (t *Token) Decode(m interface{}) error {
	var err error
	switch v := m.(type) {
	case map[string]interface{}:
		for k, v := range v {
			if err = t.decode(k, v); err != nil {
				log.WithError(err).Error("error parsing token")
				break
			}
		}
	case *Token:
		t = v
	case Token:
		t = &v
	default:
		return fmt.Errorf("cannot parse token from type %T", v)
	}
	return nil
}

type TokenDecoder interface {
	Decode(m interface{}) error
}

func (t *Token) IsExpired() error {
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
	vv := reflectValue(token.Data)

	if v.CanSet() && reflect.TypeOf(thing) == reflect.TypeOf(token.Data) {
		v.Set(vv)
	} else {
		return fmt.Errorf("thing is of type %T, expected %T", reflect.TypeOf(thing), reflect.TypeOf(token.Data))
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

func New(data interface{}, sub string, iat, exp time.Time) *Token {
	return &Token{
		Data: data,
		Sub:  sub,
		Iat:  iat,
		Exp:  exp,
	}
}
