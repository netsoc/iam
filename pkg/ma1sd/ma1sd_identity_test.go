package ma1sd

import (
	"net/http"
	"strings"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/steinfletcher/apitest"
)

func (s *ma1sdTestSuite) TestIdentity() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND email = \$1\).*LIMIT 1$`).
		WithArgs(s.user.Email).
		WillReturnRows(rows)

	result, err := s.ma1sd.identityLookup(threePid{
		Medium:  "email",
		Address: s.user.Email,
	})
	s.Require().NoError(err)

	s.Equal("email", result.Medium)
	s.Equal(s.user.Email, result.Address)
	s.Equal("localpart", result.ID.Type)
	s.Equal(strings.ToLower(s.user.Username), result.ID.Value)
}

func (s *ma1sdTestSuite) TestIdentityNonEmail() {
	_, err := s.ma1sd.identityLookup(threePid{
		Medium:  "phone",
		Address: "0851234567",
	})
	s.Regexp("supported", err.Error())
}

func (s *ma1sdTestSuite) TestIdentitySingle() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND email = \$1\).*LIMIT 1$`).
		WithArgs(s.user.Email).
		WillReturnRows(rows)

	apitest.New("identity single").
		Handler(s.ma1sd.handler).
		Post("/identity/single").
		JSON(identityOneRequest{
			Lookup: threePid{
				Medium:  "email",
				Address: s.user.Email,
			},
		}).
		Expect(s.T()).
		Status(http.StatusOK).
		End()
}

func (s *ma1sdTestSuite) TestIdentitySingleNotFound() {
	// lookup user
	email := "someuser@tcd.ie"
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND email = \$1\).*LIMIT 1$`).
		WithArgs(email).
		WillReturnRows(sqlmock.NewRows(userCols))

	apitest.New("identity single not found").
		Handler(s.ma1sd.handler).
		Post("/identity/single").
		JSON(identityOneRequest{
			Lookup: threePid{
				Medium:  "email",
				Address: email,
			},
		}).
		Expect(s.T()).
		Status(http.StatusNotFound).
		Body("{}").
		End()
}

func (s *ma1sdTestSuite) TestIdentityBulk() {
	// lookup user
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND email = \$1\).*LIMIT 1$`).
		WithArgs(s.user.Email).
		WillReturnRows(rows)

	// lookup user 2
	rows = sqlmock.NewRows(userCols)
	userRow(rows, &s.user2, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND email = \$1\).*LIMIT 1$`).
		WithArgs(s.user2.Email).
		WillReturnRows(rows)

	apitest.New("identity bulk").
		Handler(s.ma1sd.handler).
		Post("/identity/bulk").
		JSON(identityBulkRequest{
			Lookup: []threePid{
				{
					Medium:  "email",
					Address: s.user.Email,
				},
				{
					Medium:  "email",
					Address: s.user2.Email,
				},
			},
		}).
		Expect(s.T()).
		Status(http.StatusOK).
		End()
}

func (s *ma1sdTestSuite) TestIdentityBulkNotFound() {
	// lookup user
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND email = \$1\).*LIMIT 1$`).
		WithArgs(s.user.Email).
		WillReturnRows(sqlmock.NewRows(userCols))

	// lookup user 2
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user2, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE \(verified = true AND email = \$1\).*LIMIT 1$`).
		WithArgs(s.user2.Email).
		WillReturnRows(rows)

	apitest.New("identity bulk one not found").
		Handler(s.ma1sd.handler).
		Post("/identity/bulk").
		JSON(identityBulkRequest{
			Lookup: []threePid{
				{
					Medium:  "email",
					Address: s.user.Email,
				},
				{
					Medium:  "email",
					Address: s.user2.Email,
				},
			},
		}).
		Expect(s.T()).
		Status(http.StatusOK).
		Assert(bodyCheck(s.T(), identityBulkResponse{
			[]identityLookupItem{
				{
					Medium:  "email",
					Address: s.user2.Email,
					ID: id{
						Type:  "localpart",
						Value: strings.ToLower(s.user2.Username),
					},
				},
			},
		})).
		End()
}
