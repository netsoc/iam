package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
)

func (s *endpointsTestSuite) TestGetUserByID() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// user list
	cleanRows := sqlmock.NewRows(cleanUserCols)
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

	u2.Password = nil
	apitest.New("get user by id").
		Handler(s.server.http.Handler).
		Getf("/v1/users/id:%v", u2.ID).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(bodyCheck(s.T(), u2)).
		End()
}

func (s *endpointsTestSuite) TestGetUserByIDNonExistent() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// user list
	sqlCols := make([]string, len(cleanUserCols))
	for i, col := range cleanUserCols {
		sqlCols[i] = fmt.Sprintf(`"users"."%v"`, col)
	}
	s.dbMock.ExpectQuery(fmt.Sprintf(`^SELECT %v FROM "users"`, strings.Join(sqlCols, ","))).
		WillReturnRows(sqlmock.NewRows(cleanUserCols))

	apitest.New("get user by id where user doesn't exist").
		Handler(s.server.http.Handler).
		Getf("/v1/users/id:%v", 1234).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusNotFound).
		Assert(jsonpath.Matches("$.message", "user does not exist")).
		End()
}

func (s *endpointsTestSuite) TestGetUserByIDNonAdmin() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	s.jwt.IsAdmin = false
	apitest.New("get user by id as non-admin").
		Handler(s.server.http.Handler).
		Getf("/v1/users/id:%v", s.user.ID).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "only admin")).
		End()
}
func (s *endpointsTestSuite) TestGetUser() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// user get
	getRows := sqlmock.NewRows(userCols)
	u2 := s.user
	u2.ID = 69
	u2.Email = "dude@tcd.ie"
	u2.Username = "dude"
	userRow(getRows, &u2, s.pwHash)

	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1`).
		WithArgs(u2.Username).
		WillReturnRows(getRows)

	u2.Password = nil
	apitest.New("get user").
		Handler(s.server.http.Handler).
		Getf("/v1/users/%v", u2.Username).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(bodyCheck(s.T(), u2)).
		End()
}

func (s *endpointsTestSuite) TestGetUserSelf() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	s.user.Password = nil
	apitest.New("get self user").
		Handler(s.server.http.Handler).
		Get("/v1/users/self").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(bodyCheck(s.T(), s.user)).
		End()
}

func (s *endpointsTestSuite) TestGetUserOtherNonAdmin() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	apitest.New("get user as non-admin").
		Handler(s.server.http.Handler).
		Getf("/v1/users/%v", "someother").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "admin")).
		End()
}

func (s *endpointsTestSuite) TestGetUserOtherExpiredAdmin() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	s.jwt.Expiry = 0
	apitest.New("get user as expired admin").
		Handler(s.server.http.Handler).
		Getf("/v1/users/%v", "someother").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "admin")).
		End()
}

func (s *endpointsTestSuite) TestDeleteUser() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// get user
	getRows := sqlmock.NewRows(userCols)
	u2 := s.user
	u2.ID = 69
	u2.Email = "dude@tcd.ie"
	u2.Username = "dude"
	userRow(getRows, &u2, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1`).
		WithArgs(u2.Username).
		WillReturnRows(getRows)

	// delete user
	s.dbMock.ExpectExec(`^DELETE FROM "users" WHERE "users"\."id" = \$1$`).
		WithArgs(u2.ID).
		WillReturnResult(sqlmock.NewResult(int64(u2.ID), 1))

	u2.Password = nil
	apitest.New("delete user").
		Handler(s.server.http.Handler).
		Deletef("/v1/users/%v", u2.Username).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(bodyCheck(s.T(), u2)).
		End()
}

func (s *endpointsTestSuite) TestDeleteUserSelf() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// delete user
	s.dbMock.ExpectExec(`^DELETE FROM "users" WHERE "users"\."id" = \$1$`).
		WithArgs(s.user.ID).
		WillReturnResult(sqlmock.NewResult(int64(s.user.ID), 1))

	s.user.Password = nil
	apitest.New("delete user (self)").
		Handler(s.server.http.Handler).
		Delete("/v1/users/self").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(bodyCheck(s.T(), s.user)).
		End()
}

func (s *endpointsTestSuite) TestDeleteUserOtherNonAdmin() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	apitest.New("delete user as non-admin").
		Handler(s.server.http.Handler).
		Deletef("/v1/users/%v", "someother").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "admin")).
		End()
}
