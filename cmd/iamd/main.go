package main

import (
	"os"
	"os/signal"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/netsoc/iam/pkg/iamd"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
)

func init() {
	// Config defaults
	viper.SetDefault("log_level", log.InfoLevel)

	// Config file loading
	viper.SetConfigType("yaml")
	viper.SetConfigName("iam")
	viper.AddConfigPath("/run/config")
	viper.AddConfigPath(".")

	// Config from environment
	viper.SetEnvPrefix("iamd")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Config from flags
	pflag.StringP("log_level", "l", "info", "log level")
	pflag.Parse()
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		log.WithError(err).Fatal("Failed to bind pflags to config")
	}

	if err := viper.ReadInConfig(); err != nil {
		log.WithError(err).Debug("Failed to read config")
	}
}

func reload() {
	var config iamd.Config
	if err := viper.Unmarshal(&config, iamd.ConfigDecoderOptions); err != nil {
		log.WithField("err", err).Fatal("Failed to parse configuration")
	}

	log.SetLevel(config.LogLevel)
	log.WithField("config", config).Debug("Got config")
}

func main() {
	sigs := make(chan os.Signal)
	signal.Notify(sigs, unix.SIGINT, unix.SIGTERM)

	viper.OnConfigChange(func(e fsnotify.Event) {
		log.WithField("file", e.Name).Info("Config changed, reloading")
		reload()
	})
	viper.WatchConfig()
	reload()

	<-sigs
}
