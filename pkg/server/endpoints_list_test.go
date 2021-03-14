package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"

	"github.com/netsoc/iam/pkg/models"
)

func (s *endpointsTestSuite) TestGetUsers() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// user list
	cleanRows := sqlmock.NewRows(cleanUserCols)
	cleanUserRow(cleanRows, &s.user)
	u2 := s.user
	u2.ID = 69
	u2.Email = "dude@tcd.ie"
	u2.Username = "dude"
	cleanUserRow(cleanRows, &u2)

	sqlCols := make([]string, len(cleanUserCols))
	for i, col := range cleanUserCols {
		sqlCols[i] = fmt.Sprintf(`"users"."%v"`, col)
	}
	s.dbMock.ExpectQuery(fmt.Sprintf(`^SELECT %v FROM "users"`, strings.Join(sqlCols, ","))).
		WillReturnRows(cleanRows)

	s.user.Password = nil
	u2.Password = nil
	apitest.New("list users").
		Handler(s.server.http.Handler).
		Get("/v1/users").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(bodyCheck(s.T(), []models.User{s.user, u2})).
		End()
}

func (s *endpointsTestSuite) TestGetUsersExpired() {
	s.jwt.Expiry = 0
	apitest.New("list users with expired token").
		Handler(s.server.http.Handler).
		Get("/v1/users").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Matches("$.message", "token is expired")).
		End()
}

func (s *endpointsTestSuite) TestGetUsersNonAdmin() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	s.jwt.IsAdmin = false
	apitest.New("list users as non-admin").
		Handler(s.server.http.Handler).
		Get("/v1/users").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "only admin")).
		End()
}

func (s *endpointsTestSuite) TestGetUsersNonAdminToken() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	s.jwt.IsAdmin = true
	apitest.New("list users as non-admin (with admin token)").
		Handler(s.server.http.Handler).
		Get("/v1/users").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "only admin")).
		End()
}

func (s *endpointsTestSuite) TestGetUsersRolled() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	s.jwt.Version = 1
	apitest.New("list users with old token (still valid)").
		Handler(s.server.http.Handler).
		Get("/v1/users").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Matches("$.message", "expired")).
		End()
}
