package ma1sd

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/netsoc/iam/pkg/models"
)

var userCols = []string{"id", "username", "email", "password", "first_name", "last_name", "ssh_key", "verified", "renewed", "is_admin", "token_version", "created", "updated", "deleted"}

func userRow(rows *sqlmock.Rows, u *models.User, pwHash string) {
	rows.AddRow(u.ID, u.Username, u.Email, pwHash, u.FirstName, u.LastName, u.SSHKey, u.Verified, u.Renewed, u.IsAdmin, u.TokenVersion, u.Meta.Created, u.Meta.Updated, u.Meta.Deleted)
}

type apiAssertFunc = func(*http.Response, *http.Request) error

func bodyCheck(t assert.TestingT, obj interface{}) apiAssertFunc {
	return func(resp *http.Response, req *http.Request) error {
		dataA, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("failed to encode obj: %w", err)
		}

		defer resp.Body.Close()
		dataB, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read body: %w", err)
		}

		assert.JSONEq(t, string(dataA), string(dataB))
		return nil
	}
}

type ma1sdTestSuite struct {
	suite.Suite

	ma1sd  *MA1SD
	dbMock sqlmock.Sqlmock

	user   models.User
	user2  models.User
	pwHash string

	authReq    authRequest
	profileReq profileRequest
}

func (s *ma1sdTestSuite) SetupTest() {
	t := true
	now := time.Now()

	pass := "hunter22"
	s.user = models.User{
		ID: 123,

		Username:  "Bro",
		Email:     "root@tcd.ie",
		Password:  &pass,
		FirstName: "Root",
		LastName:  "Netsoc",
		SSHKey:    nil,

		Verified: &t,
		Renewed:  now.Add(-23 * time.Hour),
		IsAdmin:  &t,

		TokenVersion: 3,
		Meta: models.UserMeta{
			Created: now.Add(-100 * time.Hour),
			Updated: now.Add(-5 * time.Hour),
			Deleted: gorm.DeletedAt{},
		},
	}
	s.user2 = s.user
	s.user2.ID = 45
	s.user2.Username = "dUde"
	s.user.Email = "another@tcd.ie"
	s.user2.FirstName = "Some"
	s.user2.LastName = "Dude"

	// hunter22
	s.pwHash = "$2y$12$MpYHQJXagcdJe.zLp8HR0upNyuw6d6se3XOoi/wlAEeKLGCMyvmye"

	s.authReq = authRequest{
		Auth: Auth{
			MXID:      "@bro:netsoc.ie",
			LocalPart: "bro",
			Domain:    "netsoc.ie",
			Password:  pass,
		},
	}

	s.profileReq = profileRequest{
		MXID:      fmt.Sprintf("@%v:netsoc.ie", strings.ToLower(s.user.Username)),
		LocalPart: strings.ToLower(s.user.Username),
		Domain:    "netsoc.ie",
	}
}

func (s *ma1sdTestSuite) SetupSuite() {
	var err error

	var sqlDB *sql.DB
	sqlDB, s.dbMock, err = sqlmock.New()
	s.Require().NoError(err)

	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}))
	s.Require().NoError(err)

	s.ma1sd = NewMA1SD("netsoc.ie", 365*24*time.Hour, db)
}

func (s *ma1sdTestSuite) AfterTest(_, _ string) {
	s.Require().NoError(s.dbMock.ExpectationsWereMet())
}

func TestMA1SDSuite(t *testing.T) {
	suite.Run(t, new(ma1sdTestSuite))
}
