package server

import (
	"net/http"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
)

func (s *endpointsTestSuite) TestLogoutUser() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// update user
	username := "broasd"
	s.dbMock.ExpectExec(`^UPDATE "users" SET "token_version"=token_version \+ \$1 WHERE username = \$2$`).
		WithArgs(1, username).
		WillReturnResult(sqlmock.NewResult(12345, 1))

	apitest.New("logout user").
		Handler(s.server.http.Handler).
		Deletef("/v1/users/%v/login", username).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusNoContent).
		End()
}

func (s *endpointsTestSuite) TestLogoutUserSelf() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "token_version"=token_version \+ \$1 WHERE username = \$2$`).
		WithArgs(1, s.user.Username).
		WillReturnResult(sqlmock.NewResult(12345, 1))

	apitest.New("logout user (self)").
		Handler(s.server.http.Handler).
		Delete("/v1/users/self/login").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusNoContent).
		End()
}

func (s *endpointsTestSuite) TestLogoutUserNonAdmin() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// update user
	username := "broasd"
	apitest.New("logout user as non-admin").
		Handler(s.server.http.Handler).
		Deletef("/v1/users/%v/login", username).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "admin")).
		End()
}

func (s *endpointsTestSuite) TestLogoutUserNonExistent() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// update user
	username := "broasd"
	s.dbMock.ExpectExec(`^UPDATE "users" SET "token_version"=token_version \+ \$1 WHERE username = \$2$`).
		WithArgs(1, username).
		WillReturnResult(sqlmock.NewResult(12345, 0))

	apitest.New("logout non-existent user").
		Handler(s.server.http.Handler).
		Deletef("/v1/users/%v/login", username).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusNotFound).
		Assert(jsonpath.Matches("$.message", "not exist")).
		End()
}
