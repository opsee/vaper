package vaper

import (
	"testing"
	"time"

	_ "github.com/opsee/basic/schema"
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
}

var (
	testKey    = []byte{194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133}
	bearerToke = "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiI4ZHBsWGkzNzcwamNva0g5IiwidGFnIjoiWjV1aHhzdFBPY3E3dUUyS0lWcHlGdyJ9.IivL8Lsvn14iVZiQVtd_KQ.2-q6fahxJyVRYjui.4i_MJ_fAmcVEex06i_A0dKAJkKBCCpeb4uU9c_zCUSqXrnKamu7UD4Q9NB5BfGTLqK6TB7Zj5nCc4udejcKx9f_bCqcf89Jfm1keCnSE3NGmhihEpynAolFE1YGaIUPUinJMo9TmCLoSSBm9GyzL9Ombkf8I5D3peHoj9r0Y4dcwZMw7OFTZByTQ6b0oMYmrAuGvi85ZZU5ObTO-VbAy6m45XJfb_mFFx2RFliM8Dm61r60FhdrkME0ZcWjtdWo-GqIl-YtWqOVC-n6r-hSHg5g.upEmBJ4IufBcD9X03S3ofg"
	_          = Suite(&TokenSuite{})
)

func Test(t *testing.T) { TestingT(t) }

func (s *TokenSuite) SetUpTest(c *C) {
	Init(testKey)
}

func (s *TokenSuite) TestMarshalUnmarshalValidToken(c *C) {
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

	token := New(user, user.Email, now, now.Add(time.Hour*1))

	b, err := token.Marshal()
	if err != nil {
		c.Fatal(err)
	}

	ntoken, err := Unmarshal(string(b))
	c.Assert(err, IsNil)
	log.Debugf("unmarshaled token %v", ntoken)
	if nuser, ok := token.Thing.(*TestUser); ok {
		log.Debugf("unmarshaled user %v", nuser)
		c.Assert(nuser.Id, DeepEquals, 1)
		c.Assert(nuser.Email, DeepEquals, "vapin@vape.it")
		c.Assert(nuser.CreatedAt, DeepEquals, now)
		c.Assert(nuser.Admin, DeepEquals, true)
		c.Assert(nuser.DumbId, DeepEquals, int32(666))
		c.Assert(nuser.Perms, DeepEquals, perms)
	}
}

func (s *TokenSuite) TestLegacyReify(c *C) {
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

	token := New(user, user.Email, now, now.Add(time.Hour*1))

	b, err := token.Marshal()
	if err != nil {
		c.Fatal(err)
	}

	ntoken, err := Unmarshal(string(b))
	c.Assert(err, IsNil)
	log.Debugf("unmarshaled token %v", ntoken)
	nuser := &TestUser{}

	token.Reify(nuser)
	log.Debugf("reified user %v", nuser)
	c.Assert(nuser.Id, DeepEquals, 1)
	c.Assert(nuser.Email, DeepEquals, "vapin@vape.it")
	c.Assert(nuser.CreatedAt, DeepEquals, now)
	c.Assert(nuser.Admin, DeepEquals, true)
	c.Assert(nuser.DumbId, DeepEquals, int32(666))
	c.Assert(nuser.Perms, DeepEquals, perms)
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

	token := New(user, user.Email, now, now.Add(time.Hour*-1))

	b, err := token.Marshal()
	if err != nil {
		c.Fatal(err)
	}

	ntoken, err := Unmarshal(string(b))
	c.Assert(err, DeepEquals, ErrorTokenExpired)
	log.Debugf("unmarshaled token %v", ntoken)
	if nuser, ok := token.Thing.(*TestUser); ok {
		log.Debugf("unmarshaled user %v", nuser)
		c.Assert(nuser.Id, DeepEquals, 1)
		c.Assert(nuser.Email, DeepEquals, "vapin@vape.it")
		c.Assert(nuser.CreatedAt, DeepEquals, now)
		c.Assert(nuser.Admin, DeepEquals, true)
		c.Assert(nuser.DumbId, DeepEquals, int32(666))
		c.Assert(nuser.Perms, DeepEquals, perms)
	}
}
