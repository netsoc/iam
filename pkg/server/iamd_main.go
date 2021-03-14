//+build !test

package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/netsoc/iam/pkg/models"
)

// Start starts the iamd server
func (s *Server) Start() error {
	var err error
	pg := &s.config.PostgreSQL
	dsn := strings.TrimSpace(fmt.Sprintf("host=%v user=%v password=%v dbname=%v TimeZone=%v %v",
		pg.Host,
		pg.User,
		pg.Password,
		pg.Database,
		pg.TimeZone,
		pg.DSNExtra,
	))
	s.db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to open connection to database: %w", err)
	}

	if err := s.db.AutoMigrate(&models.User{}); err != nil {
		return fmt.Errorf("failed to run database auto migration: %w", err)
	}

	var count int64
	if err := s.db.Model(&models.User{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to count users: %w", err)
	}

	if count == 0 {
		t := true
		root := models.User{
			Username:  "root",
			Email:     "root@tcd.ie",
			Password:  &s.config.RootPassword,
			FirstName: "Root",
			LastName:  "Netsoc",

			Verified: &t,
			Renewed:  time.Now(),
			IsAdmin:  &t,
		}

		log.WithField("password", root.Password).Info("Database empty, creating root user")
		if err := s.db.Create(&root).Error; err != nil {
			return fmt.Errorf("failed to create root user: %w", err)
		}
	}

	eChan := make(chan error)
	go func() {
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			eChan <- fmt.Errorf("failed to start HTTP server: %w", err)
		}

		eChan <- nil
	}()

	if s.ma1sd != nil {
		go func() {
			s.ma1sd.DB = s.db
			if err := s.httpMA1SD.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				eChan <- fmt.Errorf("failed to start ma1sd HTTP server: %w", err)
			}

			eChan <- nil
		}()
	}

	return <-eChan
}

// Stop shuts down the iamd server
func (s *Server) Stop() error {
	ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)

	if s.ma1sd != nil {
		if err := s.httpMA1SD.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shut down ma1sd HTTP server: %w", err)
		}
	}

	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shut down HTTP server: %w", err)
	}

	db, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get SQL DB: %w", err)
	}

	if err := db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	return nil
}
