package ma1sd

import (
	"net/http"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
)

func (s *ma1sdTestSuite) TestAuth() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE LOWER\(username\) = \$1.*LIMIT 1$`).
		WithArgs(strings.ToLower(s.user.Username)).
		WillReturnRows(rows)

	apitest.New("auth").
		Handler(s.ma1sd.handler).
		Post("/auth/login").
		JSON(s.authReq).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(jsonpath.Chain().
			Equal("auth.success", true).
			Equal("auth.id.type", "localpart").
			Equal("auth.profile.display_name", s.user.FirstName+" "+s.user.LastName).
			Equal("auth.profile.three_pids[0].medium", "email").
			Equal("auth.profile.three_pids[0].address", s.user.Email).
			End()).
		End()
}

func (s *ma1sdTestSuite) TestAuthWrongDomain() {
	s.authReq.Auth.Domain = "example.com"
	apitest.New("auth wrong domain").
		Handler(s.ma1sd.handler).
		Post("/auth/login").
		JSON(s.authReq).
		Expect(s.T()).
		Status(http.StatusBadRequest).
		End()
}

func (s *ma1sdTestSuite) TestAuthNonExistent() {
	// lookup user
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE LOWER\(username\) = \$1.*LIMIT 1$`).
		WithArgs(strings.ToLower(s.user.Username)).
		WillReturnRows(sqlmock.NewRows(userCols))

	apitest.New("auth non-existent").
		Handler(s.ma1sd.handler).
		Post("/auth/login").
		JSON(s.authReq).
		Expect(s.T()).
		Status(http.StatusNotFound).
		End()
}

func (s *ma1sdTestSuite) TestAuthUnverified() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	f := false
	s.user.Verified = &f
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE LOWER\(username\) = \$1.*LIMIT 1$`).
		WithArgs(strings.ToLower(s.user.Username)).
		WillReturnRows(rows)

	apitest.New("auth unverified").
		Handler(s.ma1sd.handler).
		Post("/auth/login").
		JSON(s.authReq).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		End()
}

func (s *ma1sdTestSuite) TestAuthNotRenewed() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	s.user.Renewed = time.Unix(0, 0)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE LOWER\(username\) = \$1.*LIMIT 1$`).
		WithArgs(strings.ToLower(s.user.Username)).
		WillReturnRows(rows)

	apitest.New("auth not renewed").
		Handler(s.ma1sd.handler).
		Post("/auth/login").
		JSON(s.authReq).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		End()
}

func (s *ma1sdTestSuite) TestAuthBadPassword() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE LOWER\(username\) = \$1.*LIMIT 1$`).
		WithArgs(strings.ToLower(s.user.Username)).
		WillReturnRows(rows)

	s.authReq.Auth.Password = "asd123"
	apitest.New("auth bad password").
		Handler(s.ma1sd.handler).
		Post("/auth/login").
		JSON(s.authReq).
		Expect(s.T()).
		Status(http.StatusUnauthorized).
		End()
}
