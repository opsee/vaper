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
	Thing     interface{} `token:"thing"`
	Exp       time.Time   `token:"exp"`
	Iat       time.Time   `token:"iat"`
	Sub       string      `token:"sub"`
	NotLegacy bool        `token:"notlegacy"`
}

func (t *Token) sortTime(k string, v interface{}) error {
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

func (t *Token) sort(k string, v interface{}) error {
	log.Debugf("sorting %s, %T", k, v)
	switch k {
	case "iat", "exp":
		return t.sortTime(k, v)
	case "sub":
		if kv, ok := v.(string); ok {
			t.Sub = kv
		} else {
			return fmt.Errorf("invalid value %v for key \"sub\"", kv)
		}
	case "thing":
		t.Thing = v
	case "notlegacy":
		t.NotLegacy = true
	default:
		return fmt.Errorf("encountered unknown field")
	}
	return nil
}

// Creates a token from map[string]interface{}.
// NOTE: needed because we must unmarshal legacy token to map[string]interface{}
func (t *Token) New(m interface{}) (*Token, error) {
	var err error
	switch v := m.(type) {
	case map[string]interface{}:
		for k, v := range v {
			if err = t.sort(k, v); err != nil {
				log.WithError(err).Error("error parsing token")
				break
			}
		}
	case *Token:
		t = v
	case Token:
		t = &v
	default:
		return nil, fmt.Errorf("cannot parse token from type %T", v)
	}
	t.NotLegacy = true
	return t, nil
}

func (t *Token) Marshal() (string, error) {
	b, err := MarshalToken(t, &MarshalOpts{Crypto: cryptOpts})
	return string(b), err
}

type TokenMaker interface {
	New(m interface{}) (*Token, error)
}

func (t *Token) UnmarshalToken(b []byte) error {
	var p map[string]interface{}
	err := UnmarshalToken(b, &p, &UnmarshalOpts{Crypto: nil, CallIface: true})
	if err != nil {
		return err
	}

	log.Debugf("unmarshaled %v", p)
	// all new tokens have notlegacy set
	if notl, ok := p["notlegacy"]; ok {
		if z, ok := notl.(bool); z && ok {
			nt := &Token{}
			toke, err := nt.New(p)
			if err == nil && toke != nil {
				*t = *toke
			}
			*t = *nt
			return err
		}
		return fmt.Errorf("invalid value for reserved key \"notlegacy\"")
	}

	// try to parse it as a legacy token
	legacy := &Legacy{}
	toke, err := legacy.New(p)
	if err == nil {
		*t = *legacy.Token
		reflectValue(t).Set(reflectValue(toke))
	}
	return err
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

func (token *Token) LegacyReify(thing interface{}) error {
	t := reflectValue(thing)

	for i := 0; i < t.NumField(); i++ {
		tag := t.Type().Field(i).Tag.Get("token")
		kind := t.Field(i).Kind()

		val, ok := token.Thing.(map[string]interface{})[tag]
		if !ok {
			continue
		}

		switch val.(type) {
		case float64: // a special case for json turning things into floats
			switch kind {
			case reflect.Int, reflect.Int32, reflect.Int64:
				t.Field(i).SetInt(int64(val.(float64)))
			default:
				t.Field(i).Set(reflect.ValueOf(val))
			}
		case string: // a special case for timestamps
			if kind == reflect.Struct {
				date, err := time.Parse(time.RFC3339, val.(string))
				if err != nil {
					return err
				}
				t.Field(i).Set(reflect.ValueOf(date))
			} else {
				t.Field(i).Set(reflect.ValueOf(val))
			}
		default:
			t.Field(i).Set(reflect.ValueOf(val))
		}
	}

	return nil

}

func (token *Token) Reify(thing interface{}) error {
	if token.NotLegacy {
		v := reflectValue(thing)
		vv := reflectValue(token.Thing)

		if v.CanSet() && reflect.TypeOf(thing) == reflect.TypeOf(token.Thing) {
			v.Set(vv)
		} else {
			return fmt.Errorf("thing is of type %T, expected %T", reflect.TypeOf(thing), reflect.TypeOf(token.Thing))
		}
	} else {
		return token.LegacyReify(thing)
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
	err := UnmarshalToken([]byte(tokenString), token, &UnmarshalOpts{Crypto: cryptOpts, CallIface: true})
	if err != nil {
		return nil, err
	}
	log.Debugf("resultant token: %+v", *token)

	if err = token.Expired(); err != nil {
		return token, err
	}

	return token, nil
}

func New(thing interface{}, sub string, iat, exp time.Time) *Token {
	return &Token{
		Thing:     thing,
		Sub:       sub,
		Iat:       iat,
		Exp:       exp,
		NotLegacy: true, // must be set
	}
}
