package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func (s *userTestSuite) TestCreateUser() {
	// check existing user by username
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Username).
		WillReturnRows(sqlmock.NewRows(userCols))

	// check existing user by email
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE email = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Email).
		WillReturnRows(sqlmock.NewRows(userCols))

	sqlCols := make([]string, len(createCols))
	sqlArgs := make([]string, len(createCols))
	for i, col := range createCols {
		sqlCols[i] = fmt.Sprintf(`"%v"`, col)
		sqlArgs[i] = fmt.Sprintf(`\$%v`, i+1)
	}

	f := false
	t := true
	s.selfCreate.ID = 123
	s.selfCreate.Verified = &f
	s.selfCreate.IsAdmin = &t
	s.selfCreate.TokenVersion = 1
	s.selfCreate.Meta = UserMeta{
		Created: time.Now(),
		Updated: time.Now(),
	}
	s.dbMock.ExpectQuery(fmt.Sprintf(`^INSERT INTO "users" \(%v\) VALUES \(%v\) RETURNING "id"$`, strings.Join(sqlCols, ","), strings.Join(sqlArgs, ","))).
		WithArgs(userArgs(&s.selfCreate)...).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(s.selfCreate.ID))

	copy := s.selfCreate
	copy.ID = 6969
	copy.TokenVersion = 1234
	s.NoError(s.db.Create(&copy).Error, "GORM creates user successfully")

	s.selfCreate.Password = copy.Password
	s.selfCreate.Meta = copy.Meta
	s.Equal(s.selfCreate, copy, "GORM user is correct")
}

func (s *userTestSuite) TestCreateEmptyPassword() {
	// check existing user by username
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Username).
		WillReturnRows(sqlmock.NewRows(userCols))

	// check existing user by email
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE email = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Email).
		WillReturnRows(sqlmock.NewRows(userCols))

	sqlCols := make([]string, len(createCols))
	sqlArgs := make([]string, len(createCols))
	for i, col := range createCols {
		sqlCols[i] = fmt.Sprintf(`"%v"`, col)
		sqlArgs[i] = fmt.Sprintf(`\$%v`, i+1)
	}

	f := false
	t := true
	blank := ""
	s.selfCreate.ID = 123
	s.selfCreate.Verified = &f
	s.selfCreate.IsAdmin = &t
	s.selfCreate.TokenVersion = 1
	s.selfCreate.Password = &blank
	s.selfCreate.Meta = UserMeta{
		Created: time.Now(),
		Updated: time.Now(),
	}

	// Override password check
	args := userArgs(&s.selfCreate)
	args[2] = ""

	sqlmock.NewRows([]string{"id"}).AddRow(s.selfCreate.ID)
	s.dbMock.ExpectQuery(fmt.Sprintf(`^INSERT INTO "users" \(%v\) VALUES \(%v\) RETURNING "id"$`, strings.Join(sqlCols, ","), strings.Join(sqlArgs, ","))).
		WithArgs(args...).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(s.selfCreate.ID))

	copy := s.selfCreate
	copy.ID = 6969
	copy.TokenVersion = 1234
	s.NoError(s.db.Create(&copy).Error, "GORM creates user successfully")

	s.selfCreate.Meta = copy.Meta
	s.Equal(s.selfCreate, copy, "GORM user is correct")
}

func (s *userTestSuite) TestCreateUserExistsUsername() {
	// check existing user by username
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Username).
		WillReturnRows(rows)

	s.selfCreate.Email = "mybro@tcd.ie"
	copy := s.selfCreate
	s.ErrorIs(s.db.Create(&copy).Error, ErrUsernameExists, "GORM fails to create user")
}

func (s *userTestSuite) TestCreateUserExistsEmail() {
	// check existing user by username
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Username).
		WillReturnRows(sqlmock.NewRows(userCols))

	// check existing user by email
	s.selfCreate.Username = "otherbro"
	rows := sqlmock.NewRows(userCols)
	userRow(rows, &s.user, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE email = \$1.*LIMIT 1$`).
		WithArgs(s.selfCreate.Email).
		WillReturnRows(rows)

	s.selfCreate.Username = "bro"
	copy := s.selfCreate
	s.ErrorIs(s.db.Create(&copy).Error, ErrEmailExists, "GORM fails to create user")
}

func (s *userTestSuite) TestCreateUserMissingEmail() {
	s.selfCreate.Email = ""

	copy := s.selfCreate
	err := s.db.Create(&copy).Error
	s.Require().Error(err, "GORM fails to create user")
	s.Regexp("email.*blank", err)
}

func (s *userTestSuite) TestCreateUserInvalidEmail() {
	s.selfCreate.Email = "bromail"

	copy := s.selfCreate
	err := s.db.Create(&copy).Error
	s.Require().Error(err, "GORM fails to create user")
	s.Regexp("valid email", err)
}

func (s *userTestSuite) TestCreateUserMissingUsername() {
	s.selfCreate.Username = ""

	copy := s.selfCreate
	err := s.db.Create(&copy).Error
	s.Require().Error(err, "GORM fails to create user")
	s.Regexp("username.*blank", err)
}

func (s *userTestSuite) TestCreateUserInvalidUsername() {
	s.selfCreate.Username = "bro!dude"

	copy := s.selfCreate
	err := s.db.Create(&copy).Error
	s.Require().Error(err, "GORM fails to create user")
	s.Regexp("valid DNS", err)
}

func (s *userTestSuite) TestCreateUserShortPassword() {
	p := "hunter2"
	s.selfCreate.Password = &p

	copy := s.selfCreate
	err := s.db.Create(&copy).Error
	s.Require().Error(err, "GORM fails to create user")
	s.Regexp("password.*length", err)
}

func (s *userTestSuite) TestCreateUserMissingName() {
	s.selfCreate.FirstName = ""
	s.selfCreate.LastName = ""

	copy := s.selfCreate
	err := s.db.Create(&copy).Error
	s.Require().Error(err, "GORM fails to create user")
	s.Regexp("name.*blank", err)
}
