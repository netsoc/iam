package server

import (
	"net/http"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
	"github.com/stretchr/testify/mock"

	"github.com/netsoc/iam/pkg/email"
)

func (s *endpointsTestSuite) TestVerifyGenerate() {
	// get user
	getRows := sqlmock.NewRows(userCols)
	f := false
	s.user.Verified = &f
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1`).
		WithArgs(s.user.Username).
		WillReturnRows(getRows)

	s.emailMock.On("SendEmail", email.VerificationAPI, email.VerificationSubject, mock.Anything).Once().Return(nil)

	apitest.New("generate email verification").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v/login", s.user.Username).
		Expect(s.T()).
		Status(http.StatusNoContent).
		End()
}

func (s *endpointsTestSuite) TestVerifyGenerateNonExistent() {
	// get user
	f := false
	s.user.Verified = &f
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1`).
		WithArgs(s.user.Username).
		WillReturnRows(sqlmock.NewRows(userCols))

	apitest.New("generate email verification non-existent user").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v/login", s.user.Username).
		Expect(s.T()).
		Status(http.StatusNotFound).
		Assert(jsonpath.Matches("$.message", "not exist")).
		End()
}

func (s *endpointsTestSuite) TestVerifyGenerateVerified() {
	// get user
	getRows := sqlmock.NewRows(userCols)
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1`).
		WithArgs(s.user.Username).
		WillReturnRows(getRows)

	apitest.New("generate email verification non-existent user").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v/login", s.user.Username).
		Expect(s.T()).
		Status(http.StatusBadRequest).
		Assert(jsonpath.Matches("$.message", "already verified")).
		End()
}

func (s *endpointsTestSuite) TestVerifyToken() {
	// check user
	getRows := sqlmock.NewRows(userCols)
	f := false
	s.user.Verified = &f
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1`).
		WithArgs(s.user.ID).
		WillReturnRows(getRows)

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "verified"=\$1,"token_version"=\$2 WHERE "id" = \$3$`).
		WithArgs(true, s.user.TokenVersion+1, s.user.ID).
		WillReturnResult(sqlmock.NewResult(12345, 1))

	s.jwt = s.jwtVerify
	apitest.New("do email verification").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v/login", s.user.Username).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusNoContent).
		End()
}

func (s *endpointsTestSuite) TestVerifyTokenOther() {
	// check user
	getRows := sqlmock.NewRows(userCols)
	f := false
	s.user.Verified = &f
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1`).
		WithArgs(s.user.ID).
		WillReturnRows(getRows)

	s.jwt = s.jwtVerify
	apitest.New("do email verification for another account").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v/login", "somebro").
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusBadRequest).
		Assert(jsonpath.Matches("$.message", "own account")).
		End()
}

func (s *endpointsTestSuite) TestVerifyTokenWrongJWT() {
	s.jwt = s.jwtReset
	apitest.New("do email verification with incorrect type of jwt").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v/login", s.user.Username).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Matches("$.message", "audience")).
		End()
}

func (s *endpointsTestSuite) TestVerifyTokenWrongVersionJWT() {
	// check user
	getRows := sqlmock.NewRows(userCols)
	f := false
	s.user.Verified = &f
	userRow(getRows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1`).
		WithArgs(s.user.ID).
		WillReturnRows(getRows)

	s.jwtVerify.Version = 0
	s.jwt = s.jwtVerify
	apitest.New("do email verification with wrong version of jwt").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v/login", s.user.Username).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Matches("$.message", "expired")).
		End()
}
