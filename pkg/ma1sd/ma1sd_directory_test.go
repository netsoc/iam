package ma1sd

import (
	"net/http"
	"strings"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
)

func (s *ma1sdTestSuite) TestDirectory() {
	// search for users
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(LOWER\(CONCAT\(first_name, ' ', last_name\)\) LIKE \$1 AND verified = true\).*$`).
		WithArgs("%etso%").
		WillReturnRows(rows)

	apitest.New("directory").
		Handler(s.ma1sd.handler).
		Post("/directory/user/search").
		JSON(`{
			"by": "name",
			"search_term": "EtSo"
		}`).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(jsonpath.Chain().
			Equal("limited", false).
			NotPresent("results[0].avatar_url").
			Equal("results[0].display_name", s.user.FirstName+" "+s.user.LastName).
			Equal("results[0].user_id", strings.ToLower(s.user.Username)).
			End()).
		End()
}

func (s *ma1sdTestSuite) TestDirectoryEmail() {
	// search for users
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	userRow(rows, &s.user2, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(email LIKE \$1 AND verified = true\).*$`).
		WithArgs("%tcd%").
		WillReturnRows(rows)

	apitest.New("directory by email").
		Handler(s.ma1sd.handler).
		Post("/directory/user/search").
		JSON(`{
			"by": "threepid",
			"search_term": "tcd"
		}`).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(jsonpath.Chain().
			Equal("limited", false).
			NotPresent("results[0].avatar_url").
			Equal("results[0].display_name", s.user.FirstName+" "+s.user.LastName).
			Equal("results[0].user_id", strings.ToLower(s.user.Username)).
			NotPresent("results[1].avatar_url").
			Equal("results[1].display_name", s.user2.FirstName+" "+s.user2.LastName).
			Equal("results[1].user_id", strings.ToLower(s.user2.Username)).
			End()).
		End()
}

func (s *ma1sdTestSuite) TestDirectoryEmpty() {
	// search for users
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(email LIKE \$1 AND verified = true\).*$`).
		WithArgs("%asdtcd%").
		WillReturnRows(sqlmock.NewRows(userCols))

	apitest.New("directory empty").
		Handler(s.ma1sd.handler).
		Post("/directory/user/search").
		JSON(`{
			"by": "threepid",
			"search_term": "asdtcd"
		}`).
		Expect(s.T()).
		Status(http.StatusOK).
		Body(`{
			"limited": false,
			"results": []
		}`).
		End()
}
