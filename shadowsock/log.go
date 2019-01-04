package shadowsock

import (
	"github.com/natefinch/lumberjack"
	logrus "github.com/sirupsen/logrus"
)

var log = newLog()

func newLog() (log *logrus.Logger) {
	log = logrus.New()
	log.SetLevel(logrus.DebugLevel)
	log.Formatter = &logrus.TextFormatter{
		ForceColors:      true,
		FullTimestamp:    true,
		TimestampFormat:  "2006-01-02 15:04:05",
		QuoteEmptyFields: true,
	}

	log.Out = &lumberjack.Logger{
		Filename:   "./logs/ss-server.log",
		MaxSize:    50,
		MaxBackups: 10,
		MaxAge:     30,
		Compress:   true,
		LocalTime:  true,
	}

	return
}
