package main

import (
	"os"
	"os/signal"
	"strings"

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
	log.WithField("config", config).Debug("Got config")

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
