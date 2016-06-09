package vaper

import (
	"testing"
	"time"

	_ "github.com/opsee/basic/schema"
	opsee_types "github.com/opsee/protobuf/opseeproto/types"

	. "gopkg.in/check.v1"
)

type TokenSuite struct{}
type testUser struct {
	Id                 int       `token:"id"`
	Email              string    `token:"email"`
	CreatedAt          time.Time `token:"created_at"`
	Admin              bool      `token:"admin"`
	DumbId             int32     `token:"dumb_id"`
	ThisFieldIsIgnored bool
	TeamFlags          *opsee_types.Permission `token:"team_flags"`
	Perms              *opsee_types.Permission `token:"perms"`
}

var (
	testVapeKey = []byte{194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133}
	bearerToke  = "eyJhbGciOiJBMTI4R0NNS1ciLCJlbmMiOiJBMTI4R0NNIiwiaXYiOiI4ZHBsWGkzNzcwamNva0g5IiwidGFnIjoiWjV1aHhzdFBPY3E3dUUyS0lWcHlGdyJ9.IivL8Lsvn14iVZiQVtd_KQ.2-q6fahxJyVRYjui.4i_MJ_fAmcVEex06i_A0dKAJkKBCCpeb4uU9c_zCUSqXrnKamu7UD4Q9NB5BfGTLqK6TB7Zj5nCc4udejcKx9f_bCqcf89Jfm1keCnSE3NGmhihEpynAolFE1YGaIUPUinJMo9TmCLoSSBm9GyzL9Ombkf8I5D3peHoj9r0Y4dcwZMw7OFTZByTQ6b0oMYmrAuGvi85ZZU5ObTO-VbAy6m45XJfb_mFFx2RFliM8Dm61r60FhdrkME0ZcWjtdWo-GqIl-YtWqOVC-n6r-hSHg5g.upEmBJ4IufBcD9X03S3ofg"
	_           = Suite(&TokenSuite{})
)

func Test(t *testing.T) { TestingT(t) }

func (s *TokenSuite) SetUpTest(c *C) {
	Init(testVapeKey)
}

func (s *TokenSuite) TestNew(c *C) {
	now := time.Now()
	exp := now.Add(time.Hour * 1)
	token := newTestToken(now, exp)

	c.Assert((*token)["exp"], DeepEquals, exp.Unix())
	c.Assert((*token)["ThisFieldIsIgnored"], DeepEquals, nil)
	c.Assert((*token)["email"], DeepEquals, "vapin@vape.it")
	c.Assert((*token)["sub"], DeepEquals, "vapin@vape.it")
}

func (s *TokenSuite) TestToke(c *C) {
	_, err := Unmarshal(bearerToke)
	if err != nil {
		c.Fatal(err)
	}
}

func (s *TokenSuite) TestReify(c *C) {
	now := time.Now().UTC()
	exp := now.Add(time.Hour * 1)
	token := newTestToken(now, exp)

	tokenString, err := token.Marshal()
	if err != nil {
		c.Fatal(err)
	}

	decoded, err := Unmarshal(tokenString)
	if err != nil {
		c.Fatal(err)
	}

	user := &testUser{}
	decoded.Reify(user)

	c.Assert(user.Id, DeepEquals, 1)
	c.Assert(user.Email, DeepEquals, "vapin@vape.it")
	c.Assert(user.CreatedAt, DeepEquals, now)
	c.Assert(user.Admin, DeepEquals, true)
	c.Assert(user.DumbId, DeepEquals, int32(666))
}

func (s *TokenSuite) TestMarshalUnmarshal(c *C) {
	now := time.Now().UTC()
	exp := now.Add(time.Hour * 1)
	token := newTestToken(now, exp)
	tokenString, err := token.Marshal()
	if err != nil {
		c.Fatal(err)
	}

	decoded, err := Unmarshal(tokenString)
	if err != nil {
		c.Fatal(err)
	}

	c.Assert((*decoded)["exp"], DeepEquals, exp.Unix())
	c.Assert((*decoded)["ThisFieldIsIgnored"], DeepEquals, nil)
	c.Assert((*decoded)["email"], DeepEquals, "vapin@vape.it")
	c.Assert((*decoded)["sub"], DeepEquals, "vapin@vape.it")
	c.Assert((*decoded)["perms"], DeepEquals, map[string]interface{}{"name": "user", "perms": []interface{}{"admin"}})
	c.Assert((*decoded)["team_flags"], DeepEquals, map[string]interface{}{"name": "team_flags", "perms": []interface{}{"external_check"}})
}

func (s *TokenSuite) TestVerify(c *C) {
	now := time.Now().UTC()
	exp := now.Add(time.Hour * 1)
	tokenString, err := newTestToken(now, exp).Marshal()
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(Verify(tokenString), IsNil)

	now = time.Now().Add(time.Hour * 1)
	exp = now.Add(time.Hour * 2)
	tokenString, err = newTestToken(now, exp).Marshal()
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(Verify(tokenString), ErrorMatches, ".*issued after now")

	now = time.Now()
	exp = now.Add(time.Hour * -2)
	tokenString, err = newTestToken(now, exp).Marshal()
	if err != nil {
		c.Fatal(err)
	}
	c.Assert(Verify(tokenString), ErrorMatches, ".*expired")
}

func newTestToken(now, exp time.Time) *Token {
	perms, _ := opsee_types.NewPermissions("user", "admin")
	teamflags, _ := opsee_types.NewPermissions("team_flags", "external_check")

	user := &testUser{
		Id:                 1,
		Email:              "vapin@vape.it",
		CreatedAt:          now,
		Admin:              true,
		ThisFieldIsIgnored: true,
		DumbId:             int32(666),
		TeamFlags:          teamflags,
		Perms:              perms,
	}

	return New(user, "vapin@vape.it", now, exp)
}
