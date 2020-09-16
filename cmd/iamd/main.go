package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/netsoc/iam/pkg/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
)

var srv *server.Server

func init() {
	// Config defaults
	viper.SetDefault("log_level", log.InfoLevel)
	viper.SetDefault("db.dsn", "host=db user=iamd password=hunter2 dbname=iamd TimeZone=Europe/Dublin")
	viper.SetDefault("db.soft_delete", true)
	viper.SetDefault("http_address", ":80")
	viper.SetDefault("jwt.key", []byte{})
	viper.SetDefault("jwt.issuer", "iamd")
	viper.SetDefault("jwt.login_validity", 365*24*time.Hour)
	viper.SetDefault("root_password", "hunter22")

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
		log.WithError(err).Warn("Failed to read config")
	}
}

func reload() {
	if srv != nil {
		stop()
		srv = nil
	}

	var config server.Config
	if err := viper.Unmarshal(&config, server.ConfigDecoderOptions); err != nil {
		log.WithField("err", err).Fatal("Failed to parse configuration")
	}

	log.SetLevel(config.LogLevel)
	cJSON, err := json.Marshal(config)
	if err != nil {
		log.WithError(err).Fatal("Failed to encode config as JSON")
	}
	log.WithField("config", string(cJSON)).Debug("Got config")

	if config.JWT.KeyFile != "" {
		var err error
		config.JWT.Key, err = ioutil.ReadFile(config.JWT.KeyFile)
		if err != nil {
			log.WithError(err).Fatal("Failed to read JWT key file")
		}
	}
	if len(config.JWT.Key) < 32 {
		log.Fatal("JWT secret must be at least 32 bytes!")
	}

	srv = server.NewServer(config)

	log.Info("Starting server")
	go func() {
		if err := srv.Start(); err != nil {
			log.WithError(err).Fatal("Failed to start server")
		}
	}()
}

func stop() {
	if err := srv.Stop(); err != nil {
		log.WithError(err).Fatal("Failed to stop iamd server")
	}
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
	stop()
}
