package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
)

// base64ToBytesHookFunc returns a mapstructure.DecodeHookFunc which parses a []byte from a Base64 string
func base64ToBytesHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.Slice || t.Elem().Kind() != reflect.Uint8 {
			return data, nil
		}

		return base64.StdEncoding.DecodeString(data.(string))
	}
}

// stringToLogLevelHookFunc returns a mapstructure.DecodeHookFunc which parses a logrus Level from a string
func stringToLogLevelHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.TypeOf(log.InfoLevel).Kind() {
			return data, nil
		}

		var level log.Level
		err := level.UnmarshalText([]byte(data.(string)))
		return level, err
	}
}

// ConfigDecoderOptions enables necessary mapstructure decode hook functions
func ConfigDecoderOptions(config *mapstructure.DecoderConfig) {
	config.ErrorUnused = true
	config.DecodeHook = mapstructure.ComposeDecodeHookFunc(
		base64ToBytesHookFunc(),
		config.DecodeHook,
		stringToLogLevelHookFunc(),
	)
}

// Config defines iamd's configuration
type Config struct {
	LogLevel log.Level `mapstructure:"log_level"`

	PostgreSQL struct {
		Host         string
		User         string
		Password     string
		PasswordFile string `mapstructure:"password_file"`
		Database     string
		TimeZone     string
		DSNExtra     string `mapstructure:"dsn_extra"`

		SoftDelete bool `mapstructure:"soft_delete"`
	}

	Mail struct {
		From      string
		ReplyTo   string `mapstructure:"reply_to"`
		VerifyURL string `mapstructure:"verify_url"`
		ResetURL  string `mapstructure:"reset_url"`

		SMTP struct {
			Host     string
			Port     uint16
			Username string
			Password string
			TLS      bool

			PasswordFile string `mapstructure:"password_file"`
		}
	}

	HTTP struct {
		ListenAddress string `mapstructure:"listen_address"`
		CORS          struct {
			AllowedOrigins []string `mapstructure:"allowed_origins"`
		}
	}

	JWT struct {
		Key     []byte `mapstructure:"key"`
		KeyFile string `mapstructure:"key_file"`

		Issuer        string
		LoginValidity time.Duration `mapstructure:"login_validity"`
		EmailValidity time.Duration `mapstructure:"email_validity"`
	}

	RootPassword     string `mapstructure:"root_password"`
	RootPasswordFile string `mapstructure:"root_password_file"`

	ReservedUsernames []string `mapstructure:"reserved_usernames"`

	MA1SD struct {
		HTTPAddress string `mapstructure:"http_address"`
		BaseURL     string `mapstructure:"base_url"`
		Domain      string
	}
}

// ReadSecrets loads values for secret config options from files
func (c *Config) ReadSecrets() error {
	if c.PostgreSQL.PasswordFile != "" {
		pw, err := ioutil.ReadFile(c.PostgreSQL.PasswordFile)
		if err != nil {
			return fmt.Errorf("failed to read PostgreSQL password file: %w", err)
		}

		c.PostgreSQL.Password = strings.TrimSpace(string(pw))
	}

	if c.Mail.SMTP.PasswordFile != "" {
		pw, err := ioutil.ReadFile(c.Mail.SMTP.PasswordFile)
		if err != nil {
			return fmt.Errorf("failed to read SMTP password file: %w", err)
		}

		c.Mail.SMTP.Password = strings.TrimSpace(string(pw))
	}

	if c.JWT.KeyFile != "" {
		var err error
		c.JWT.Key, err = ioutil.ReadFile(c.JWT.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to read JWT key file: %w", err)
		}
	}
	if len(c.JWT.Key) < 32 {
		return errors.New("JWT secret must be at least 32 bytes")
	}

	if c.RootPasswordFile != "" {
		pw, err := ioutil.ReadFile(c.RootPasswordFile)
		if err != nil {
			return fmt.Errorf("failed to read root password file: %w", err)
		}

		c.RootPassword = strings.TrimSpace(string(pw))
	}

	return nil
}

// JWTKeyFunc returns a function that will return the JWT key (for use with `jwt` package)
func (c *Config) JWTKeyFunc() jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		return c.JWT.Key, nil
	}
}
