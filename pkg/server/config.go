package server

import (
	"encoding/base64"
	"reflect"
	"time"

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

	DB struct {
		DSN        string
		SoftDelete bool `mapstructure:"soft_delete"`
	}

	HTTPAddress string `mapstructure:"http_address"`
	JWT         struct {
		Key     []byte `mapstructure:"key"`
		KeyFile string `mapstructure:"key_file"`

		Issuer        string
		LoginValidity time.Duration `mapstructure:"login_validity"`
	}
}
