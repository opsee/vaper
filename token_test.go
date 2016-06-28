package vaper

import (
	"testing"
	"time"

	"github.com/opsee/basic/schema"
	opsee_types "github.com/opsee/protobuf/opseeproto/types"
	log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

type TokenSuite struct{}
type TestUser struct {
	Id                 int       `token:"id"`
	Email              string    `token:"email"`
	CreatedAt          time.Time `token:"created_at"`
	Admin              bool      `token:"admin"`
	DumbId             int32     `token:"dumb_id"`
	ThisFieldIsIgnored bool
	Perms              *opsee_types.Permission `token:"perms"`
	UFlags             *schema.UserFlags       `token:"uflags"`
}

var (
	testKey = []byte{194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133}
	_       = Suite(&TokenSuite{})
)

func Test(t *testing.T) { TestingT(t) }

func (s *TokenSuite) SetUpTest(c *C) {
	Init(testKey)
}

func (s *TokenSuite) TestMarshalUnmarshalValidToken(c *C) {
	now := time.Now().UTC()
	perms, err := opsee_types.NewPermissions("user", "admin")
	uflags := &schema.UserFlags{Admin: true}
	user := &TestUser{
		Id:                 1,
		Email:              "vapin@vape.it",
		CreatedAt:          now,
		Admin:              true,
		ThisFieldIsIgnored: true,
		DumbId:             int32(666),
		Perms:              perms,
		UFlags:             uflags,
	}

	token := New(user, user.Email, now, now.Add(time.Hour*1))
	b, err := MarshalToken(token, &MarshalOpts{Crypto: cryptOpts})
	c.Assert(err, IsNil)

	nt := &Token{}
	err = UnmarshalToken(b, nt, &UnmarshalOpts{Crypto: cryptOpts})
	c.Assert(err, IsNil)
	log.Debugf("test unmarshaled token %v", nt)
	if nu, ok := token.Data.(*TestUser); ok {
		log.Debugf("test unmarshaled user %v", nu)
		c.Assert(nu.Id, DeepEquals, 1)
		c.Assert(nu.Email, DeepEquals, "vapin@vape.it")
		c.Assert(nu.CreatedAt, DeepEquals, now)
		c.Assert(nu.Admin, DeepEquals, true)
		c.Assert(nu.DumbId, DeepEquals, int32(666))
		c.Assert(nu.Perms, DeepEquals, perms)
		c.Assert(nu.UFlags, DeepEquals, uflags)
	}
}

func (s *TokenSuite) TestMarshalUnmarshalExpiredToken(c *C) {
	now := time.Now().UTC()
	perms, err := opsee_types.NewPermissions("user", "admin")
	user := &TestUser{
		Id:                 1,
		Email:              "vapin@vape.it",
		CreatedAt:          now,
		Admin:              true,
		ThisFieldIsIgnored: true,
		DumbId:             int32(666),
		Perms:              perms,
	}

	token := New(user, user.Email, now, now.Add(time.Hour-1))
	b, err := MarshalToken(token, &MarshalOpts{Crypto: cryptOpts})
	c.Assert(err, IsNil)

	nt := &Token{}
	err = UnmarshalToken(b, nt, &UnmarshalOpts{Crypto: cryptOpts})
	log.Debugf("test unmarshaled token %v", nt)
	if nu, ok := token.Data.(*TestUser); ok {
		log.Debugf("test unmarshaled user %v", nu)
		c.Assert(nu.Id, DeepEquals, 1)
		c.Assert(nu.Email, DeepEquals, "vapin@vape.it")
		c.Assert(nu.CreatedAt, DeepEquals, now)
		c.Assert(nu.Admin, DeepEquals, true)
		c.Assert(nu.DumbId, DeepEquals, int32(666))
		c.Assert(nu.Perms, DeepEquals, perms)
	}
}
