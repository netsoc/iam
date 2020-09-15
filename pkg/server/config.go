package server

import (
	"reflect"

	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
)

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
}
