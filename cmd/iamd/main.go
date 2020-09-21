package main

import (
	"encoding/json"
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

	viper.SetDefault("postgresql.host", "db")
	viper.SetDefault("postgresql.user", "iamd")
	viper.SetDefault("postgresql.password", "hunter2")
	viper.SetDefault("postgresql.password_file", "")
	viper.SetDefault("postgresql.database", "iamd")
	viper.SetDefault("postgresql.timezone", "Europe/Dublin")
	viper.SetDefault("postgresql.dsn_extra", "")
	viper.SetDefault("postgresql.soft_delete", true)

	viper.SetDefault("mail.from", `"Netsoc IAM" <iam@netsoc.ie>`)
	viper.SetDefault("mail.reply_to", `"Netsoc Support" <support@netsoc.ie>`)
	viper.SetDefault("mail.verify_url", "https://account.netsoc.ie/verify?token={{.Token}}")
	viper.SetDefault("mail.reset_url", "https://account.netsoc.ie/reset?token={{.Token}}")

	viper.SetDefault("mail.smtp.host", "mail")
	viper.SetDefault("mail.smtp.port", 587)
	viper.SetDefault("mail.smtp.username", "iam@netsoc.ie")
	viper.SetDefault("mail.smtp.password", "hunter2")
	viper.SetDefault("mail.smtp.password_file", "")
	viper.SetDefault("mail.smtp.tls", false)

	viper.SetDefault("http.listen_address", ":80")
	viper.SetDefault("http.cors.allowed_origins", []string{"*"})

	viper.SetDefault("jwt.key", []byte{})
	viper.SetDefault("jwt.key_file", "")
	viper.SetDefault("jwt.issuer", "iamd")
	viper.SetDefault("jwt.login_validity", 365*24*time.Hour)
	viper.SetDefault("jwt.email_validity", 24*time.Hour)

	viper.SetDefault("root_password", "hunter22")
	viper.SetDefault("root_password_file", "")

	// Config file loading
	viper.SetConfigType("yaml")
	viper.SetConfigName("iamd")
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

	if err := config.ReadSecrets(); err != nil {
		log.WithError(err).Fatal("Failed to read config secrets from files")
	}

	log.SetLevel(config.LogLevel)
	cJSON, err := json.Marshal(config)
	if err != nil {
		log.WithError(err).Fatal("Failed to encode config as JSON")
	}
	log.WithField("config", string(cJSON)).Debug("Got config")

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
