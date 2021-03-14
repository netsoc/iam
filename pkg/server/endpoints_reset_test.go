package server

import (
	"net/http"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/netsoc/iam/pkg/email"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
	"github.com/stretchr/testify/mock"
)

func (s *endpointsTestSuite) TestResetGenerate() {
	// get user
	getRows := sqlmock.NewRows(userCols)
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1`).
		WithArgs(s.user.Username).
		WillReturnRows(getRows)

	s.emailMock.On("SendEmail", email.ResetPasswordAPI, email.ResetPasswordSubject, mock.Anything).Once().Return(nil)

	apitest.New("generate password reset").
		Handler(s.server.http.Handler).
		Putf("/v1/users/%v/login", s.user.Username).
		Expect(s.T()).
		Status(http.StatusNoContent).
		End()
}

func (s *endpointsTestSuite) TestResetGenerateNonExistent() {
	// get user
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1`).
		WithArgs(s.user.Username).
		WillReturnRows(sqlmock.NewRows(userCols))

	apitest.New("generate password reset non-existent user").
		Handler(s.server.http.Handler).
		Putf("/v1/users/%v/login", s.user.Username).
		Expect(s.T()).
		Status(http.StatusNotFound).
		Assert(jsonpath.Matches("$.message", "not exist")).
		End()
}

func (s *endpointsTestSuite) TestResetGenerateUnverified() {
	// get user
	f := false
	s.user.Verified = &f
	getRows := sqlmock.NewRows(userCols)
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1`).
		WithArgs(s.user.Username).
		WillReturnRows(getRows)

	apitest.New("generate password reset unverified user").
		Handler(s.server.http.Handler).
		Putf("/v1/users/%v/login", s.user.Username).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Matches("$.message", "not verified")).
		End()
}

func (s *endpointsTestSuite) TestResetToken() {
	// check user
	getRows := sqlmock.NewRows(userCols)
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1`).
		WithArgs(s.user.ID).
		WillReturnRows(getRows)

	req := passwordReq{Password: "somethingsafe"}

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "password"=\$1,"token_version"=\$2 WHERE "id" = \$3$`).
		WithArgs(argBcrypt(req.Password), s.user.TokenVersion+1, s.user.ID).
		WillReturnResult(sqlmock.NewResult(12345, 1))

	s.jwt = s.jwtReset
	apitest.New("do password reset").
		Handler(s.server.http.Handler).
		Putf("/v1/users/%v/login", s.user.Username).
		JSON(req).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusNoContent).
		End()
}

func (s *endpointsTestSuite) TestResetTokenOther() {
	// check user
	getRows := sqlmock.NewRows(userCols)
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1`).
		WithArgs(s.user.ID).
		WillReturnRows(getRows)

	s.jwt = s.jwtReset
	apitest.New("do password reset for another account").
		Handler(s.server.http.Handler).
		Putf("/v1/users/%v/login", "somebro").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusBadRequest).
		Assert(jsonpath.Matches("$.message", "own account")).
		End()
}

func (s *endpointsTestSuite) TestResetTokenBlank() {
	// check user
	getRows := sqlmock.NewRows(userCols)
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1`).
		WithArgs(s.user.ID).
		WillReturnRows(getRows)

	s.jwt = s.jwtReset
	apitest.New("do password reset with blank password").
		Handler(s.server.http.Handler).
		Putf("/v1/users/%v/login", s.user.Username).
		JSON(passwordReq{}).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusBadRequest).
		Assert(jsonpath.Matches("$.message", "required")).
		End()
}

func (s *endpointsTestSuite) TestResetTokenWrongJWT() {
	s.jwt = s.jwtVerify
	apitest.New("do password reset with incorrect type of jwt").
		Handler(s.server.http.Handler).
		Putf("/v1/users/%v/login", s.user.Username).
		JSON(passwordReq{Password: "somethingsecure"}).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Matches("$.message", "audience")).
		End()
}

func (s *endpointsTestSuite) TestResetTokenWrongVersionJWT() {
	// check user
	getRows := sqlmock.NewRows(userCols)
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1`).
		WithArgs(s.user.ID).
		WillReturnRows(getRows)

	s.jwtReset.Version = 0
	s.jwt = s.jwtReset
	apitest.New("do password reset with wrong version of jwt").
		Handler(s.server.http.Handler).
		Putf("/v1/users/%v/login", s.user.Username).
		JSON(passwordReq{Password: "somethingsecure"}).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Matches("$.message", "expired")).
		End()
}
