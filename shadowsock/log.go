package shadowsocks

import (
	"github.com/natefinch/lumberjack"
	logrus "github.com/sirupsen/logrus"
)

var log = newLog()

func newLog() (log *logrus.Logger) {
	log := logrus.New()
	log.SetLevel(logrus.DebugLevel)
	log.Formatter = &logrus.JSONFormater{}

	log.Out = &lumberjack.Logger{
		Filename:   "./logs/ss-server.log",
		MaxSize:    50,
		MaxBackups: 10,
		MaxAge:     30,
		Compress:   true,
		LocalTime:  true,
	}
}
