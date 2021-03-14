package models

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var (
	userCols   = []string{"id", "username", "email", "password", "first_name", "last_name", "ssh_key", "verified", "renewed", "is_admin", "token_version", "created", "updated", "deleted"}
	createCols = []string{"username", "email", "password", "first_name", "last_name", "ssh_key", "verified", "renewed", "is_admin", "token_version", "created", "updated", "deleted"}
)

func userRow(rows *sqlmock.Rows, u *User, pwHash string) {
	rows.AddRow(u.ID, u.Username, u.Email, pwHash, u.FirstName, u.LastName, u.SSHKey, u.Verified, u.Renewed, u.IsAdmin, u.TokenVersion, u.Meta.Created, u.Meta.Updated, u.Meta.Deleted)
}
func userArgs(u *User) []driver.Value {
	return []driver.Value{u.Username, u.Email, argBcrypt(*u.Password), u.FirstName, u.LastName, u.SSHKey, u.Verified, u.Renewed, u.IsAdmin, u.TokenVersion, argWithin{u.Meta.Created, time.Second}, argWithin{u.Meta.Updated, time.Second}, u.Meta.Deleted}
}

type argBcrypt string

func (b argBcrypt) Match(v driver.Value) bool {
	h, ok := v.(string)
	if !ok {
		return false
	}

	if err := bcrypt.CompareHashAndPassword([]byte(h), []byte(b)); err != nil {
		fmt.Fprintf(os.Stderr, "bcrypt error: %v", err)
		return false
	}

	return true
}

type argWithin struct {
	Expected time.Time
	Delta    time.Duration
}

func (w argWithin) Match(v driver.Value) bool {
	t, ok := v.(time.Time)
	if !ok {
		return false
	}

	dt := w.Expected.Sub(t)
	if dt < -w.Delta || dt > w.Delta {
		return false
	}

	return true
}

type testJWT struct {
	Audience  []string `json:"aud,omitempty"`
	Expiry    float64  `json:"exp"`
	Issued    float64  `json:"iat"`
	Issuer    string   `json:"iss,omitempty"`
	NotBefore float64  `json:"nbf"`
	Subject   string   `json:"sub,omitempty"`
	IsAdmin   bool     `json:"is_admin,omitempty"`
	Version   uint     `json:"version,omitempty"`
}

func jwtLoad(jwt string, key []byte) (testJWT, error) {
	var t testJWT

	split := strings.Split(jwt, ".")

	gotMAC, err := ioutil.ReadAll(base64.NewDecoder(base64.URLEncoding.WithPadding(base64.NoPadding), strings.NewReader(split[2])))
	if err != nil {
		return t, fmt.Errorf("failed to decode HMAC base64: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(split[0]))
	mac.Write([]byte{'.'})
	mac.Write([]byte(split[1]))
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(expectedMAC, gotMAC) {
		return t, errors.New("JWT MAC invalid")
	}

	data, err := ioutil.ReadAll(base64.NewDecoder(base64.URLEncoding.WithPadding(base64.NoPadding), strings.NewReader(split[1])))
	if err != nil {
		return t, fmt.Errorf("failed to decode claims base64: %w", err)
	}

	if err := json.Unmarshal(data, &t); err != nil {
		return t, fmt.Errorf("failed to decode JWT: %w", err)
	}

	return t, nil
}

type userTestSuite struct {
	suite.Suite

	db     *gorm.DB
	dbMock sqlmock.Sqlmock

	user         User
	selfCreate   User
	nonAdminSave User
	pwHash       string

	jwtKey []byte
}

func (s *userTestSuite) AfterTest(_, _ string) {
	s.Require().NoError(s.dbMock.ExpectationsWereMet())
}

func (s *userTestSuite) SetupSuite() {
	var err error

	var db *sql.DB
	db, s.dbMock, err = sqlmock.New()
	s.Require().NoError(err)

	s.db, err = gorm.Open(postgres.New(postgres.Config{Conn: db}))
	s.Require().NoError(err)

	s.jwtKey = []byte("test")
}

func (s *userTestSuite) SetupTest() {
	t := true
	now := time.Now()

	pass := "hunter22"
	s.selfCreate = User{
		Username:  "bro",
		Email:     "bro@tcd.ie",
		Password:  &pass,
		FirstName: "Bro",
		LastName:  "Dude",
	}

	k := "asd"
	s.nonAdminSave = User{
		Email:    "bro2@tcd.ie",
		Password: &pass,
		LastName: "Dude",
		SSHKey:   &k,
	}

	s.user = User{
		ID: 123,

		Username:  "bro",
		Email:     "root@tcd.ie",
		Password:  &pass,
		FirstName: "Root",
		LastName:  "Netsoc",
		SSHKey:    nil,

		Verified: &t,
		Renewed:  now.Add(-23 * time.Hour),
		IsAdmin:  &t,

		TokenVersion: 3,
		Meta: UserMeta{
			Created: now.Add(-100 * time.Hour),
			Updated: now.Add(-5 * time.Hour),
			Deleted: gorm.DeletedAt{},
		},
	}

	// hunter22
	s.pwHash = "$2y$12$MpYHQJXagcdJe.zLp8HR0upNyuw6d6se3XOoi/wlAEeKLGCMyvmye"
}

func (s *userTestSuite) TestNonAdmin() {
	s.NoError(s.nonAdminSave.NonAdminSaveOK([]string{}), "admin not required")
}

func (s *userTestSuite) TestNonAdminEmail() {
	s.nonAdminSave.Email = "bro@nottcd.ie"

	s.ErrorIs(s.nonAdminSave.NonAdminSaveOK([]string{}), ErrAdminRequired, "admin required")
}

func (s *userTestSuite) TestNonAdminVerified() {
	f := false
	s.nonAdminSave.Verified = &f

	s.ErrorIs(s.nonAdminSave.NonAdminSaveOK([]string{}), ErrAdminRequired, "admin required")
}

func (s *userTestSuite) TestNonAdminRenewed() {
	s.nonAdminSave.Renewed = time.Now()

	s.ErrorIs(s.nonAdminSave.NonAdminSaveOK([]string{}), ErrAdminRequired, "admin required")
}

func (s *userTestSuite) TestNonAdminIsAdmin() {
	f := false
	s.nonAdminSave.IsAdmin = &f

	s.ErrorIs(s.nonAdminSave.NonAdminSaveOK([]string{}), ErrAdminRequired, "admin required")
}

func (s *userTestSuite) TestNonAdminUsernameReserved() {
	s.nonAdminSave.Username = "someguy"

	s.ErrorIs(s.nonAdminSave.NonAdminSaveOK([]string{s.nonAdminSave.Username}), ErrReservedUsername, "username reserved")
}

func (s *userTestSuite) TestCheckPassword() {
	s.user.Password = &s.pwHash

	s.NoError(s.user.CheckPassword("hunter22"), "password is correct")
	s.Error(s.user.CheckPassword("hunter23"), "password is incorrect")

	s.user.Password = nil
	s.ErrorIs(s.user.CheckPassword("hunter22"), ErrLoginDisabled, "login is disabled")

	p := ""
	s.user.Password = &p
	s.ErrorIs(s.user.CheckPassword("hunter22"), ErrLoginDisabled, "login is disabled")
}

func (s *userTestSuite) TestGenerateToken() {
	issuer := "iamd"
	expiry := time.Now().Add(time.Hour)
	tokenJSON, err := s.user.GenerateToken(s.jwtKey, issuer, expiry)
	s.Require().NoError(err, "JWT generates successfully")

	t, err := jwtLoad(tokenJSON, s.jwtKey)
	s.Require().NoError(err, "JWT is valid")

	s.ElementsMatch([]string{"auth"}, t.Audience)
	s.WithinDuration(expiry, Float64Time(t.Expiry), time.Millisecond)
	s.WithinDuration(time.Now(), Float64Time(t.Issued), time.Second)
	s.Equal(issuer, t.Issuer)
	s.WithinDuration(time.Now(), Float64Time(t.NotBefore), time.Second)
	s.Equal(fmt.Sprint(s.user.ID), t.Subject)
	s.Equal(*s.user.IsAdmin, t.IsAdmin)
	s.Equal(s.user.TokenVersion, t.Version)
}

func (s *userTestSuite) TestGenerateEmailToken() {
	issuer := "iamd"
	audience := "blah"
	validity := 2 * time.Hour
	tokenJSON, err := s.user.GenerateEmailToken(s.jwtKey, issuer, audience, validity)
	s.Require().NoError(err, "JWT generates successfully")

	t, err := jwtLoad(tokenJSON, s.jwtKey)
	s.Require().NoError(err, "JWT is valid")

	s.ElementsMatch([]string{audience}, t.Audience)
	s.WithinDuration(time.Now().Add(validity), Float64Time(t.Expiry), time.Millisecond)
	s.WithinDuration(time.Now(), Float64Time(t.Issued), time.Second)
	s.Equal(issuer, t.Issuer)
	s.WithinDuration(time.Now(), Float64Time(t.NotBefore), time.Second)
	s.Equal(fmt.Sprint(s.user.ID), t.Subject)
	s.Equal(s.user.TokenVersion, t.Version)
}

func (s *userTestSuite) TestClean() {
	s.user.Clean()
	s.Nil(s.user.Password)
}

func (s *userTestSuite) TestValidAdmin() {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   fmt.Sprint(s.user.ID),
			IssuedAt:  jwt.At(time.Now()),
			NotBefore: jwt.At(time.Now()),
			ExpiresAt: jwt.At(time.Now().Add(time.Minute)),
			Issuer:    "iamd",
			Audience:  []string{"auth"},
		},
		Version: s.user.TokenVersion,
		IsAdmin: *s.user.IsAdmin,
	}

	s.True(s.user.ValidAdmin(&claims), "valid admin")

	claims.StandardClaims.ExpiresAt = jwt.At(time.Now().Add(-5 * time.Second))
	s.False(s.user.ValidAdmin(&claims), "expired admin")

	f := false
	s.user.IsAdmin = &f
	claims.StandardClaims.ExpiresAt = jwt.At(time.Now().Add(5 * time.Second))
	s.False(s.user.ValidAdmin(&claims), "valid non-admin")
}

func TestUserSuite(t *testing.T) {
	suite.Run(t, new(userTestSuite))
}
