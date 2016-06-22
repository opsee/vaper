package vaper

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

type Legacy struct {
	*Token
}

func (lt Legacy) sort(k string, v interface{}) error {
	switch k {
	case "exp", "iat":
		if kv, ok := v.(float64); ok {
			if k == "iat" {
				lt.Token.Iat = time.Unix(int64(kv), 0)
			}
			if k == "exp" {
				lt.Token.Exp = time.Unix(int64(kv), 0)
			}
		} else {
			return fmt.Errorf("invalid value %v for legacy key \"time\"", kv)
		}
	case "sub":
		if kv, ok := v.(string); ok {
			lt.Token.Sub = kv
		} else {
			return fmt.Errorf("invalid value %v for legacy key \"sub\"", kv)
		}
	default:
		lt.Token.Thing.(map[string]interface{})[k] = v
	}
	return nil
}

func (lt *Legacy) New(m interface{}) (*Token, error) {
	var err error
	switch v := m.(type) {
	case map[string]interface{}:
		lt.Token = &Token{}
		lt.Token.Thing = make(map[string]interface{})
		for k, val := range v {
			if err = lt.sort(k, val); err != nil {
				break
			}
		}
	default:
		return nil, fmt.Errorf("cannot parse legacy token from type %T", v)
	}

	log.WithError(err).Debugf("new legacy token %v", lt.Token)
	return lt.Token, err
}
