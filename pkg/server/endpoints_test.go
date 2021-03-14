package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/netsoc/iam/pkg/email"
	"github.com/netsoc/iam/pkg/models"
)

var (
	userCols      = []string{"id", "username", "email", "password", "first_name", "last_name", "ssh_key", "verified", "renewed", "is_admin", "token_version", "created", "updated", "deleted"}
	cleanUserCols = []string{"id", "username", "email", "first_name", "last_name", "ssh_key", "verified", "renewed", "is_admin", "token_version", "created", "updated", "deleted"}
)

func userRow(rows *sqlmock.Rows, u *models.User, pwHash string) {
	rows.AddRow(u.ID, u.Username, u.Email, pwHash, u.FirstName, u.LastName, u.SSHKey, u.Verified, u.Renewed, u.IsAdmin, u.TokenVersion, u.Meta.Created, u.Meta.Updated, u.Meta.Deleted)
}
func cleanUserRow(rows *sqlmock.Rows, u *models.User) {
	rows.AddRow(u.ID, u.Username, u.Email, u.FirstName, u.LastName, u.SSHKey, u.Verified, u.Renewed, u.IsAdmin, u.TokenVersion, u.Meta.Created, u.Meta.Updated, u.Meta.Deleted)
}

func tokenFromBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	tBody := tokenRes{}
	if err := json.NewDecoder(resp.Body).Decode(&tBody); err != nil {
		return "", fmt.Errorf("failed to decode response")
	}

	return tBody.Token, nil
}

type apiAssertFunc = func(*http.Response, *http.Request) error

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

func jwtCheck(checker func(testJWT)) apiAssertFunc {
	return func(resp *http.Response, req *http.Request) error {
		t, err := tokenFromBody(resp)
		if err != nil {
			return err
		}

		split := strings.Split(t, ".")
		data, err := ioutil.ReadAll(base64.NewDecoder(base64.URLEncoding.WithPadding(base64.NoPadding), strings.NewReader(split[1])))
		if err != nil {
			return fmt.Errorf("failed to decode claims base64: %w", err)
		}

		decoded := testJWT{}
		if err := json.Unmarshal(data, &decoded); err != nil {
			return fmt.Errorf("failed to decode JWT: %w", err)
		}

		checker(decoded)
		return nil
	}
}

func makeJWT(payload interface{}, key []byte) (string, error) {
	// alg: HS256, typ: JWT
	header64 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	var b bytes.Buffer
	enc := base64.NewEncoder(base64.URLEncoding.WithPadding(base64.NoPadding), &b)
	if _, err := enc.Write(payloadJSON); err != nil {
		return "", fmt.Errorf("failed to base64 encode payload: %w", err)
	}
	enc.Close()
	payload64 := b.Bytes()

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(header64))
	mac.Write([]byte{'.'})
	mac.Write(payload64)
	sum := mac.Sum(nil)

	var b2 bytes.Buffer
	enc = base64.NewEncoder(base64.URLEncoding.WithPadding(base64.NoPadding), &b2)
	if _, err := enc.Write(sum); err != nil {
		return "", fmt.Errorf("failed to base64 encode hmac: %w", err)
	}
	enc.Close()
	sum64 := b2.Bytes()

	return fmt.Sprintf("%v.%v.%v", header64, string(payload64), string(sum64)), nil
}

func bodyCheck(t assert.TestingT, obj interface{}) apiAssertFunc {
	return func(resp *http.Response, req *http.Request) error {
		dataA, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("failed to encode obj: %w", err)
		}

		defer resp.Body.Close()
		dataB, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read body: %w", err)
		}

		assert.JSONEq(t, string(dataA), string(dataB))
		return nil
	}
}

type mockEmail struct {
	mock.Mock
}

func (m *mockEmail) SendEmail(tpl *template.Template, subject string, info email.UserInfo) error {
	args := m.Called(tpl, subject, info)
	return args.Error(0)
}

func (m *mockEmail) Config() *email.Config {
	return nil
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

type endpointsTestSuite struct {
	suite.Suite

	server    *Server
	emailMock *mockEmail
	dbMock    sqlmock.Sqlmock

	user       models.User
	selfCreate models.User
	pwHash     string
	jwt        testJWT
	jwtVerify  testJWT
	jwtReset   testJWT
}

func (s *endpointsTestSuite) SetupSuite() {
	var err error
	s.server, err = NewServer(Config{
		ReservedUsernames: []string{"reserved"},
		JWT: JWTConfig{
			Key:           []byte("test"),
			Issuer:        "iamd",
			LoginValidity: 365 * 24 * time.Hour,
			EmailValidity: 24 * time.Hour,
		},
		MA1SD: MA1SDConfig{
			HTTPAddress: ":8008",
			BaseURL:     "/_ma1sd/backend/api/v1",
			Domain:      "netsoc.ie",
		},
	})
	s.Require().NoError(err)

	s.emailMock = new(mockEmail)
	s.server.email = s.emailMock

	var db *sql.DB
	db, s.dbMock, err = sqlmock.New()
	s.Require().NoError(err)

	s.server.db, err = gorm.Open(postgres.New(postgres.Config{Conn: db}))
	s.Require().NoError(err)
}

func (s *endpointsTestSuite) SetupTest() {
	t := true
	now := time.Now()

	pass := "hunter22"
	s.user = models.User{
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
		Meta: models.UserMeta{
			Created: now.Add(-100 * time.Hour),
			Updated: now.Add(-5 * time.Hour),
			Deleted: gorm.DeletedAt{},
		},
	}

	s.selfCreate = models.User{
		Username:  "bro",
		Email:     "bro@tcd.ie",
		Password:  &pass,
		FirstName: "Bro",
		LastName:  "Dude",
	}

	// hunter22
	s.pwHash = "$2y$12$MpYHQJXagcdJe.zLp8HR0upNyuw6d6se3XOoi/wlAEeKLGCMyvmye"
	s.jwt = testJWT{
		Audience:  []string{"auth"},
		Expiry:    float64(now.Add(s.server.config.JWT.LoginValidity).Unix()),
		Issued:    float64(now.Unix()),
		NotBefore: float64(now.Unix()),
		Subject:   fmt.Sprint(s.user.ID),
		Issuer:    s.server.config.JWT.Issuer,
		IsAdmin:   *s.user.IsAdmin,
		Version:   s.user.TokenVersion,
	}
	s.jwtVerify = testJWT{
		Audience:  []string{"verification"},
		Expiry:    float64(now.Add(s.server.config.JWT.EmailValidity).Unix()),
		Issued:    float64(now.Unix()),
		NotBefore: float64(now.Unix()),
		Subject:   fmt.Sprint(s.user.ID),
		Issuer:    s.server.config.JWT.Issuer,
		Version:   s.user.TokenVersion,
	}
	s.jwtReset = s.jwtVerify
	s.jwtReset.Audience = []string{"password_reset"}
}

func (s *endpointsTestSuite) jwtHeader() string {
	token, err := makeJWT(s.jwt, s.server.config.JWT.Key)
	s.Require().NoError(err)

	return "Bearer " + token
}

func (s *endpointsTestSuite) AfterTest(_, _ string) {
	s.Require().NoError(s.dbMock.ExpectationsWereMet())
}

func (s *endpointsTestSuite) TestHealth() {
	apitest.New("health check").
		Handler(s.server.http.Handler).
		Get("/health").
		Expect(s.T()).
		Status(http.StatusNoContent).
		End()
}

func (s *endpointsTestSuite) Test404() {
	apitest.New("404").
		Handler(s.server.http.Handler).
		Get("/blah").
		Expect(s.T()).
		Status(http.StatusNotFound).
		Assert(jsonpath.Matches("$.message", "not found")).
		End()
}

func (s *endpointsTestSuite) TestMethodNotAllowed() {
	apitest.New("method not allowed").
		Handler(s.server.http.Handler).
		Delete("/v1/users").
		Expect(s.T()).
		Status(http.StatusMethodNotAllowed).
		Assert(jsonpath.Matches("$.message", "not allowed")).
		End()
}

func TestEndpointsSuite(t *testing.T) {
	suite.Run(t, new(endpointsTestSuite))
}
