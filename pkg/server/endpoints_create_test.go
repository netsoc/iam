package server

import (
	"net/http"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
	"github.com/stretchr/testify/mock"

	"github.com/netsoc/iam/pkg/email"
)

func (s *endpointsTestSuite) TestCreateUser() {
	post := s.selfCreate

	// check existing user by username
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Username).
		WillReturnRows(sqlmock.NewRows(userCols))

	// check existing user by email
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE email = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Email).
		WillReturnRows(sqlmock.NewRows(userCols))

	// create user
	s.selfCreate.ID = 123
	s.dbMock.ExpectQuery(`^INSERT INTO "users" .* VALUES .* RETURNING "id"$`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(s.selfCreate.ID))

	s.emailMock.On("SendEmail", email.VerificationAPI, email.VerificationSubject, mock.Anything).Once().Return(nil)

	apitest.New("create user").
		Handler(s.server.http.Handler).
		Post("/v1/users").
		JSON(post).
		Expect(s.T()).
		Status(http.StatusCreated).
		Assert(jsonpath.Chain().
			Equal("id", float64(s.selfCreate.ID)).
			Equal("username", s.selfCreate.Username).
			Equal("email", s.selfCreate.Email).
			NotPresent("password").
			Equal("first_name", s.selfCreate.FirstName).
			Equal("last_name", s.selfCreate.LastName).
			NotPresent("ssh_key").
			Equal("verified", false).
			Equal("renewed", "0001-01-01T00:00:00Z").
			Equal("is_admin", false).
			Present("meta.created").
			Present("meta.updated").
			NotPresent("meta.deleted").
			End()).
		End()
}

func (s *endpointsTestSuite) TestCreateUserAdmin() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	t := true
	s.selfCreate.IsAdmin = &t
	post := s.selfCreate

	// check existing user by username
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Username).
		WillReturnRows(sqlmock.NewRows(userCols))

	// check existing user by email
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE email = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Email).
		WillReturnRows(sqlmock.NewRows(userCols))

	// create user
	s.selfCreate.ID = 123
	s.dbMock.ExpectQuery(`^INSERT INTO "users" .* VALUES .* RETURNING "id"$`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(s.selfCreate.ID))

	s.emailMock.On("SendEmail", email.VerificationAPI, email.VerificationSubject, mock.Anything).Once().Return(nil)

	apitest.New("create user").
		Handler(s.server.http.Handler).
		Post("/v1/users").
		Header("Authorization", s.jwtHeader()).
		JSON(post).
		Expect(s.T()).
		Status(http.StatusCreated).
		Assert(jsonpath.Chain().
			Equal("id", float64(s.selfCreate.ID)).
			Equal("is_admin", true).
			End()).
		End()
}

func (s *endpointsTestSuite) TestCreateUserReserved() {
	s.selfCreate.Username = s.server.config.ReservedUsernames[0]

	apitest.New("create user with reserved username").
		Handler(s.server.http.Handler).
		Post("/v1/users").
		JSON(s.selfCreate).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "reserved")).
		End()
}

func (s *endpointsTestSuite) TestCreateUserAdminField() {
	t := true
	s.selfCreate.Verified = &t

	apitest.New("create user with admin field").
		Handler(s.server.http.Handler).
		Post("/v1/users").
		JSON(s.selfCreate).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "admin")).
		End()
}

func (s *endpointsTestSuite) TestCreateUserAdminFieldAuth() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	t := true
	s.selfCreate.Verified = &t

	apitest.New("create user with admin field (authorized as regular user)").
		Handler(s.server.http.Handler).
		Post("/v1/users").
		Header("Authorization", s.jwtHeader()).
		JSON(s.selfCreate).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "admin")).
		End()
}

func (s *endpointsTestSuite) TestCreateUserAdminFieldExpired() {
	t := true
	s.selfCreate.Verified = &t

	s.jwt.Expiry = 0
	apitest.New("create user with admin field (expired token)").
		Handler(s.server.http.Handler).
		Post("/v1/users").
		Header("Authorization", s.jwtHeader()).
		JSON(s.selfCreate).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		Assert(jsonpath.Matches("$.message", "expired")).
		End()
}
