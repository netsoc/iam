package server

import (
	"net/http"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"

	"github.com/netsoc/iam/pkg/models"
)

func (s *endpointsTestSuite) TestUpdateUser() {
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

	k := "asd"
	f := false
	patch := models.User{
		Username: "newbro",
		SSHKey:   &k,

		IsAdmin: &f,
	}

	// check existing user by username
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(patch.Username).
		WillReturnRows(sqlmock.NewRows(userCols))

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "username"=\$1,"ssh_key"=\$2,"is_admin"=\$3,"token_version"=\$4 WHERE "id" = \$5$`).
		WithArgs(patch.Username, k, *patch.IsAdmin, u2.TokenVersion+1, u2.ID).
		WillReturnResult(sqlmock.NewResult(int64(u2.ID), 1))

	u2.Password = nil
	apitest.New("update user").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v", u2.Username).
		JSON(patch).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(bodyCheck(s.T(), u2)).
		End()
}

func (s *endpointsTestSuite) TestUpdateUserSelf() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	k := "asd"
	patch := models.User{
		SSHKey: &k,
	}

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "ssh_key"=\$1 WHERE "id" = \$2$`).
		WithArgs(k, s.user.ID).
		WillReturnResult(sqlmock.NewResult(int64(s.user.ID), 1))

	s.user.Password = nil
	apitest.New("update user (self)").
		Handler(s.server.http.Handler).
		Patch("/v1/users/self").
		JSON(patch).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(bodyCheck(s.T(), s.user)).
		End()
}

func (s *endpointsTestSuite) TestUpdateUserOtherNonExistent() {
	// check user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	// get user
	username := "broasdqwe"
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1`).
		WithArgs(username).
		WillReturnRows(sqlmock.NewRows(userCols))

	apitest.New("update other non-existent user").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v", username).
		JSON(models.User{}).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusNotFound).
		Assert(jsonpath.Matches("$.message", "does not exist")).
		End()
}

func (s *endpointsTestSuite) TestUpdateUserOtherNonAdmin() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	apitest.New("update other user as non-admin").
		Handler(s.server.http.Handler).
		Patchf("/v1/users/%v", "someguy").
		JSON(models.User{}).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "admin")).
		End()
}

func (s *endpointsTestSuite) TestUpdateUserSelfNonAdmin() {
	// check user
	f := false
	s.user.IsAdmin = &f
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE "users"."id" = \$1.*LIMIT 1$`).
		WithArgs(s.user.ID).
		WillReturnRows(rows)

	k := "asd"
	t := true
	patch := models.User{
		SSHKey: &k,

		IsAdmin: &t,
	}

	s.user.Password = nil
	apitest.New("update user (self) as non-admin").
		Handler(s.server.http.Handler).
		Patch("/v1/users/self").
		JSON(patch).
		Header("Authorization", s.jwtHeader()).
		Expect(s.T()).
		Status(http.StatusForbidden).
		Assert(jsonpath.Matches("$.message", "admin")).
		End()
}
