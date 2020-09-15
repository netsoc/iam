package models

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var bcryptRegex = regexp.MustCompile(`^\$2[ayb]\$.{56}$`)

// UserMeta holds some GORM metadata about the User
type UserMeta struct {
	Created time.Time      `json:"created" gorm:"autoCreateTime"`
	Updated time.Time      `json:"updated" gorm:"autoUpdateTime"`
	Deleted gorm.DeletedAt `json:"-" gorm:"index"`
}

// User represents a Netsoc member
type User struct {
	ID       uint   `json:"id" gorm:"primaryKey"`
	Username string `json:"username" gorm:"uniqueIndex"`
	Email    string `json:"email" gorm:"uniqueIndex"`
	Password string `json:"password,omitempty"`

	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	IsAdmin   bool   `json:"is_admin"`

	Meta UserMeta `json:"meta" gorm:"embedded"`
}

// BeforeCreate is called by GORM before creating the User
func (u *User) BeforeCreate(tx *gorm.DB) error {
	// Make sure these fields are defaults
	u.ID = 0
	u.Meta = UserMeta{}

	if err := validation.ValidateStruct(u,
		validation.Field(&u.Email, validation.Required, is.Email,
			validation.Match(regexp.MustCompile(`^\S+@tcd\.ie$`)).Error("only @tcd.ie emails are allowed")),
		validation.Field(&u.Username, validation.Required, is.DNSName),
		validation.Field(&u.Password, validation.When(u.Password != "", validation.Length(8, 128))),

		validation.Field(&u.FirstName, validation.Required),
		validation.Field(&u.LastName, validation.Required),
	); err != nil {
		return err
	}

	if err := tx.First(&User{}, "username = ?", u.Username).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to check existing users: %w", err)
		}
	} else {
		return ErrUsernameExists
	}
	if err := tx.First(&User{}, "email = ?", u.Email).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to check existing users: %w", err)
		}
	} else {
		return ErrEmailExists
	}

	if u.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		u.Password = string(hash)
	}
	return nil
}

// BeforeUpdate is called by GORM before updating the User
func (u *User) BeforeUpdate(tx *gorm.DB) error {
	// Make sure these fields are defaults
	u.ID = 0
	u.Meta = UserMeta{}

	if err := validation.ValidateStruct(u,
		validation.Field(&u.Email, is.Email,
			validation.Match(regexp.MustCompile(`^\S+@tcd\.ie$`)).Error("only @tcd.ie emails are allowed")),
		validation.Field(&u.Username, is.DNSName),
		validation.Field(&u.Password, validation.When(u.Password != "", validation.Length(8, 128))),
	); err != nil {
		return err
	}

	if u.Username != "" {
		if err := tx.First(&User{}, "username = ?", u.Username).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("failed to check existing users: %w", err)
			}
		} else {
			return ErrUsernameExists
		}
	}
	if u.Email != "" {
		if err := tx.First(&User{}, "email = ?", u.Email).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("failed to check existing users: %w", err)
			}
		} else {
			return ErrEmailExists
		}
	}

	if u.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}

		u.Password = string(hash)
	}
	return nil
}
