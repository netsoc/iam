package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"

	"github.com/netsoc/iam/pkg/models"
)

func (s *endpointsTestSuite) TestLogin() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.user.Username).
		WillReturnRows(rows)

	apitest.New("login").
		Handler(s.server.http.Handler).
		Postf("/v1/users/%v/login", s.user.Username).
		JSON(passwordReq{Password: *s.user.Password}).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(jwtCheck(func(tj testJWT) {
			s.ElementsMatch([]string{"auth"}, tj.Audience, "jwt audiences")
			s.WithinDuration(s.user.Renewed.Add(s.server.config.JWT.LoginValidity), models.Float64Time(tj.Expiry), time.Millisecond, "jwt expiry")
			s.WithinDuration(time.Now(), models.Float64Time(tj.Issued), time.Second, "jwt issue time")
			s.Equal(s.server.config.JWT.Issuer, tj.Issuer, "jwt issuer")
			s.WithinDuration(time.Now(), models.Float64Time(tj.NotBefore), time.Second, "jwt start time")
			s.Equal(fmt.Sprint(s.user.ID), tj.Subject, "jwt subject")
			s.True(tj.IsAdmin, "jwt is admin")
			s.Equal(s.user.TokenVersion, tj.Version, "jwt version")
		})).
		End()
}

func (s *endpointsTestSuite) TestLoginNotRenewed() {
	// lookup user
	s.user.Renewed = time.Unix(0, 0)
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.user.Username).
		WillReturnRows(rows)

	apitest.New("login not renewed").
		Handler(s.server.http.Handler).
		Postf("/v1/users/%v/login", s.user.Username).
		JSON(passwordReq{Password: *s.user.Password}).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(jwtCheck(func(tj testJWT) {
			s.WithinDuration(s.user.Renewed.Add(s.server.config.JWT.LoginValidity), models.Float64Time(tj.Expiry), time.Millisecond, "jwt expiry")
			s.WithinDuration(time.Now(), models.Float64Time(tj.Issued), time.Second, "jwt issue time")
			s.WithinDuration(time.Now(), models.Float64Time(tj.NotBefore), time.Second, "jwt start time")
		})).
		End()
}

func (s *endpointsTestSuite) TestLoginNonExistent() {
	// lookup user
	username := "hmmmm"
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(username).
		WillReturnRows(sqlmock.NewRows(userCols))

	apitest.New("login non-existent user").
		Handler(s.server.http.Handler).
		Postf("/v1/users/%v/login", username).
		JSON(passwordReq{Password: "asdasdqweqwe"}).
		Expect(s.T()).
		Status(http.StatusNotFound).
		Assert(jsonpath.Matches("$.message", "user does not exist")).
		End()
}

func (s *endpointsTestSuite) TestLoginUnverified() {
	// lookup user
	f := false
	s.user.Verified = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.user.Username).
		WillReturnRows(rows)

	apitest.New("login unverified user").
		Handler(s.server.http.Handler).
		Postf("/v1/users/%v/login", s.user.Username).
		JSON(passwordReq{Password: *s.user.Password}).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Matches("$.message", "not verified")).
		End()
}

func (s *endpointsTestSuite) TestLoginBadPassword() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.user.Username).
		WillReturnRows(rows)

	apitest.New("login incorrect password").
		Handler(s.server.http.Handler).
		Postf("/v1/users/%v/login", s.user.Username).
		JSON(passwordReq{Password: "test1234"}).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Equal("$.message", "incorrect password")).
		End()
}

func (s *endpointsTestSuite) TestLoginDisabled() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, "")
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.user.Username).
		WillReturnRows(rows)

	apitest.New("login with unset password").
		Handler(s.server.http.Handler).
		Postf("/v1/users/%v/login", s.user.Username).
		JSON(passwordReq{Password: "test1234"}).
		Expect(s.T()).
		Status(http.StatusBadRequest).
		Assert(jsonpath.Matches("$.message", "login is disabled")).
		End()
}
