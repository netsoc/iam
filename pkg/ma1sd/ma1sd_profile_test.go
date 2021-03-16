package ma1sd

import (
	"net/http"
	"strings"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
)

func (s *ma1sdTestSuite) TestProfileDisplayName() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND LOWER\(username\) = \$1\).*LIMIT 1$`).
		WithArgs(strings.ToLower(s.user.Username)).
		WillReturnRows(rows)

	apitest.New("profile display name").
		Handler(s.ma1sd.handler).
		Post("/profile/displayName").
		JSON(s.profileReq).
		Expect(s.T()).
		Status(http.StatusOK).
		Bodyf(`{
			"profile": {
				"display_name": "%v %v"
			}
		}`, s.user.FirstName, s.user.LastName).
		End()
}

func (s *ma1sdTestSuite) TestProfileThreePIDs() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND LOWER\(username\) = \$1\).*LIMIT 1$`).
		WithArgs(strings.ToLower(s.user.Username)).
		WillReturnRows(rows)

	apitest.New("profile 3PID's").
		Handler(s.ma1sd.handler).
		Post("/profile/threepids").
		JSON(s.profileReq).
		Expect(s.T()).
		Status(http.StatusOK).
		Bodyf(`{
			"profile": {
				"threepids": [{
					"medium": "email",
					"address": "%v"
				}]
			}
		}`, s.user.Email).
		End()
}

func (s *ma1sdTestSuite) TestProfileRoles() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND LOWER\(username\) = \$1\).*LIMIT 1$`).
		WithArgs(strings.ToLower(s.user.Username)).
		WillReturnRows(rows)

	apitest.New("profile roles").
		Handler(s.ma1sd.handler).
		Post("/profile/roles").
		JSON(s.profileReq).
		Expect(s.T()).
		Status(http.StatusOK).
		Body(`{
			"profile":{
				"roles": []
			}
		}`).
		End()
}

func (s *ma1sdTestSuite) TestProfileNotFound() {
	// lookup user
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND LOWER\(username\) = \$1\).*LIMIT 1$`).
		WithArgs(strings.ToLower(s.user.Username)).
		WillReturnRows(sqlmock.NewRows(userCols))

	apitest.New("profile not found").
		Handler(s.ma1sd.handler).
		Post("/profile/displayName").
		JSON(s.profileReq).
		Expect(s.T()).
		Status(http.StatusOK).
		Body(`{
			"profile":{}
		}`).
		End()
}

func (s *ma1sdTestSuite) TestProfileWrongDomain() {
	s.profileReq.Domain = "example.com"
	apitest.New("auth wrong domain").
		Handler(s.ma1sd.handler).
		Post("/profile/displayName").
		JSON(s.profileReq).
		Expect(s.T()).
		Status(http.StatusBadRequest).
		End()
}
