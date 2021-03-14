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

func (s *endpointsTestSuite) TestIssue() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// lookup target
	rows = sqlmock.NewRows(userCols)
	u2 := s.user
	u2.ID = 69
	u2.Email = "dude@tcd.ie"
	u2.Username = "dude"
	userRow(rows, &u2, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(u2.Username).
		WillReturnRows(rows)

	apitest.New("issue token").
		Handler(s.server.http.Handler).
		Postf("/v1/users/%v/token", u2.Username).
		Header("Authorization", s.jwtHeader()).
		JSON(issueTokenReq{Duration: "30s"}).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(jwtCheck(func(tj testJWT) {
			s.ElementsMatch([]string{"auth"}, tj.Audience, "jwt audiences")
			s.WithinDuration(time.Now().Add(30*time.Second), models.Float64Time(tj.Expiry), time.Second, "jwt expiry")
			s.WithinDuration(time.Now(), models.Float64Time(tj.Issued), time.Second, "jwt issue time")
			s.Equal(s.server.config.JWT.Issuer, tj.Issuer, "jwt issuer")
			s.WithinDuration(time.Now(), models.Float64Time(tj.NotBefore), time.Second, "jwt start time")
			s.Equal(fmt.Sprint(u2.ID), tj.Subject, "jwt subject")
			s.True(tj.IsAdmin, "jwt is admin")
			s.Equal(u2.TokenVersion, tj.Version, "jwt version")
		})).
		End()
}

func (s *endpointsTestSuite) TestIssueNonExistent() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// lookup target
	username := "asdqwe"
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(username).
		WillReturnRows(sqlmock.NewRows(userCols))

	apitest.New("issue token for non existent user").
		Handler(s.server.http.Handler).
		Postf("/v1/users/%v/token", username).
		Header("Authorization", s.jwtHeader()).
		JSON(issueTokenReq{Duration: "30s"}).
		Expect(s.T()).
		Status(http.StatusNotFound).
		Assert(jsonpath.Matches("$.message", "user does not exist")).
		End()
}

func (s *endpointsTestSuite) TestIssueNonAdmin() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	apitest.New("issue token as non-admin").
		Handler(s.server.http.Handler).
		Postf("/v1/users/%v/token", s.user.Username).
		Header("Authorization", s.jwtHeader()).
		JSON(issueTokenReq{Duration: "30s"}).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "only admin")).
		End()
}
