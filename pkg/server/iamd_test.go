package server

import (
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func (s *endpointsTestSuite) TestCleanup() {
	age := 24 * time.Hour
	toClean := int64(123)

	s.server.config.Cleanup.Interval = 30 * time.Second
	s.server.config.Cleanup.MaxAge = age

	s.dbMock.ExpectExec(`^DELETE FROM "users" WHERE verified = \$1 AND created < \$2$`).
		WithArgs(false, argTimeWithin{Expected: time.Now().Add(-age), Duration: 1 * time.Second}).
		WillReturnResult(sqlmock.NewResult(1, toClean))

	cleaned, err := s.server.CleanupUnverified()
	s.NoError(err)
	s.Equal(toClean, cleaned)
}

func (s *endpointsTestSuite) TestCleanupNone() {
	age := 24 * time.Hour

	s.server.config.Cleanup.Interval = 30 * time.Second
	s.server.config.Cleanup.MaxAge = age

	s.dbMock.ExpectExec(`^DELETE FROM "users" WHERE verified = \$1 AND created < \$2$`).
		WithArgs(false, argTimeWithin{Expected: time.Now().Add(-age), Duration: 1 * time.Second}).
		WillReturnResult(sqlmock.NewResult(1, 0))

	cleaned, err := s.server.CleanupUnverified()
	s.NoError(err)
	s.Zero(cleaned)
}
