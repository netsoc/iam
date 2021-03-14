package models

import "github.com/DATA-DOG/go-sqlmock"

func (s *userTestSuite) TestUpdateUser() {
	blank := ""
	patch := User{
		Username:  "asdqwe",
		FirstName: "QWE",
		SSHKey:    &blank,
	}

	// check existing user by username
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(patch.Username).
		WillReturnRows(sqlmock.NewRows(userCols))

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "username"=\$1,"first_name"=\$2,"ssh_key"=\$3 WHERE "id" = \$4$`).
		WithArgs(patch.Username, patch.FirstName, blank, s.user.ID).
		WillReturnResult(sqlmock.NewResult(int64(s.user.ID), 1))

	copy := s.user
	s.NoError(s.db.Model(&copy).Updates(patch).Error, "GORM updates user successfully")

	s.user.Username = patch.Username
	s.user.FirstName = patch.FirstName
	s.user.SSHKey = patch.SSHKey
	s.user.Meta.Updated = copy.Meta.Updated
	s.Equal(s.user, copy, "GORM user is correct")
}

func (s *userTestSuite) TestUpdateUserEmail() {
	k := "asd"
	patch := User{
		Email:  "mydude@tcd.ie",
		SSHKey: &k,
	}

	// check existing user by email
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE email = \$1.*LIMIT 1$`).
		WithArgs(patch.Email).
		WillReturnRows(sqlmock.NewRows(userCols))

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "email"=\$1,"ssh_key"=\$2,"verified"=\$3,"token_version"=\$4 WHERE "id" = \$5$`).
		WithArgs(patch.Email, k, false, s.user.TokenVersion+1, s.user.ID).
		WillReturnResult(sqlmock.NewResult(int64(s.user.ID), 1))

	copy := s.user
	s.NoError(s.db.Model(&copy).Updates(patch).Error, "GORM updates user successfully")

	f := false
	s.user.Email = patch.Email
	s.user.SSHKey = patch.SSHKey
	s.user.TokenVersion++
	s.user.Verified = &f
	s.user.Meta.Updated = copy.Meta.Updated
	s.Equal(s.user, copy, "GORM user is correct")
}

func (s *userTestSuite) TestUpdateUserPassword() {
	p := "verysecure"
	k := "asd"
	patch := User{
		Password: &p,
		SSHKey:   &k,
	}

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "password"=\$1,"ssh_key"=\$2,"token_version"=\$3 WHERE "id" = \$4$`).
		WithArgs(argBcrypt(p), k, s.user.TokenVersion+1, s.user.ID).
		WillReturnResult(sqlmock.NewResult(int64(s.user.ID), 1))

	copy := s.user
	s.NoError(s.db.Model(&copy).Updates(patch).Error, "GORM updates user successfully")

	s.user.Password = copy.Password
	s.user.SSHKey = patch.SSHKey
	s.user.TokenVersion++
	s.user.Meta.Updated = copy.Meta.Updated
	s.Equal(s.user, copy, "GORM user is correct")
}

func (s *userTestSuite) TestUpdateUserPasswordEmpty() {
	p := ""
	k := "asd"
	patch := User{
		Password: &p,
		SSHKey:   &k,
	}

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "password"=\$1,"ssh_key"=\$2,"token_version"=\$3 WHERE "id" = \$4$`).
		WithArgs(p, k, s.user.TokenVersion+1, s.user.ID).
		WillReturnResult(sqlmock.NewResult(int64(s.user.ID), 1))

	copy := s.user
	s.NoError(s.db.Model(&copy).Updates(patch).Error, "GORM updates user successfully")

	s.user.Password = patch.Password
	s.user.SSHKey = patch.SSHKey
	s.user.TokenVersion++
	s.user.Meta.Updated = copy.Meta.Updated
	s.Equal(s.user, copy, "GORM user is correct")
}

func (s *userTestSuite) TestUpdateUserVerified() {
	f := false
	k := "asd"
	patch := User{
		Verified: &f,
		SSHKey:   &k,
	}

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "ssh_key"=\$1,"verified"=\$2,"token_version"=\$3 WHERE "id" = \$4$`).
		WithArgs(k, *patch.Verified, s.user.TokenVersion+1, s.user.ID).
		WillReturnResult(sqlmock.NewResult(int64(s.user.ID), 1))

	copy := s.user
	s.NoError(s.db.Model(&copy).Updates(patch).Error, "GORM updates user successfully")

	s.user.Verified = patch.Verified
	s.user.SSHKey = patch.SSHKey
	s.user.TokenVersion++
	s.user.Meta.Updated = copy.Meta.Updated
	s.Equal(s.user, copy, "GORM user is correct")
}

func (s *userTestSuite) TestUpdateUserIsAdmin() {
	f := false
	k := "asd"
	patch := User{
		IsAdmin: &f,
		SSHKey:  &k,
	}

	// update user
	s.dbMock.ExpectExec(`^UPDATE "users" SET "ssh_key"=\$1,"is_admin"=\$2,"token_version"=\$3 WHERE "id" = \$4$`).
		WithArgs(k, *patch.IsAdmin, s.user.TokenVersion+1, s.user.ID).
		WillReturnResult(sqlmock.NewResult(int64(s.user.ID), 1))

	copy := s.user
	s.NoError(s.db.Model(&copy).Updates(patch).Error, "GORM updates user successfully")

	s.user.IsAdmin = patch.IsAdmin
	s.user.SSHKey = patch.SSHKey
	s.user.TokenVersion++
	s.user.Meta.Updated = copy.Meta.Updated
	s.Equal(s.user, copy, "GORM user is correct")
}

func (s *userTestSuite) TestUpdateUserTokenID() {
	k := "asd"
	patch := User{
		ID:     456,
		SSHKey: &k,
	}

	s.ErrorIs(s.db.Model(&s.user).Updates(patch).Error, ErrInternalField, "GORM fails to update user")
}

func (s *userTestSuite) TestUpdateUserTokenVersion() {
	k := "asd"
	patch := User{
		TokenVersion: 123,
		SSHKey:       &k,
	}

	s.ErrorIs(s.db.Model(&s.user).Updates(patch).Error, ErrInternalField, "GORM fails to update user")
}

func (s *userTestSuite) TestUpdateUserExistingUsername() {
	blank := ""
	patch := User{
		Username:  "asdqwe",
		FirstName: "QWE",
		SSHKey:    &blank,
	}

	// check existing user by username
	rows := sqlmock.NewRows(userCols)
	u2 := s.user
	u2.Username = patch.Username
	userRow(rows, &u2, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE username = \$1.*LIMIT 1$`).
		WithArgs(patch.Username).
		WillReturnRows(rows)

	s.ErrorIs(s.db.Model(&s.user).Updates(patch).Error, ErrUsernameExists, "GORM fails to update user")
}

func (s *userTestSuite) TestUpdateUserExistingEmail() {
	blank := ""
	patch := User{
		Email:  "mydude@tcd.ie",
		SSHKey: &blank,
	}

	// check existing user by email
	rows := sqlmock.NewRows(userCols)
	u2 := s.user
	u2.Email = patch.Email
	userRow(rows, &u2, s.pwHash)
	s.dbMock.ExpectQuery(`^SELECT \* FROM "users" WHERE email = \$1.*LIMIT 1$`).
		WithArgs(patch.Email).
		WillReturnRows(rows)

	s.ErrorIs(s.db.Model(&s.user).Updates(patch).Error, ErrEmailExists, "GORM fails to update user")
}

func (s *userTestSuite) TestUpdateUserInvalidUsername() {
	err := s.db.Model(&s.user).Updates(User{Username: "my!dude"}).Error
	s.Require().Error(err, "GORM fails to create user")
	s.Regexp("valid DNS", err)
}

func (s *userTestSuite) TestUpdateUserInvalidEmail() {
	err := s.db.Model(&s.user).Updates(User{Email: "some!@asd"}).Error
	s.Require().Error(err, "GORM fails to create user")
	s.Regexp("valid email", err)
}

func (s *userTestSuite) TestUpdateUserShortPassword() {
	p := "short"
	err := s.db.Model(&s.user).Updates(User{Password: &p}).Error
	s.Require().Error(err, "GORM fails to create user")
	s.Regexp("password.*length", err)
}
