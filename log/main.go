package log

import (
	"os"

	"github.com/toxyl/glog"
)

var (
	log = glog.NewLoggerSimple("Tor URL Scan")
)

func init() {
	glog.LoggerConfig.ShowDateTime = true
	glog.LoggerConfig.ShowIndicator = true
	glog.LoggerConfig.ShowRuntimeMilliseconds = false
	glog.LoggerConfig.ShowRuntimeSeconds = false
	glog.LoggerConfig.ShowSubsystem = false
}

func Blank(format string, a ...interface{}) {
	log.BlankAuto(format, a...)
}

func Warn(format string, a ...interface{}) {
	log.WarningAuto(format, a...)
}

func Error(format string, a ...interface{}) {
	log.ErrorAuto(format, a...)
}

func Fatal(format string, a ...interface{}) {
	log.ErrorAuto(glog.WrapDarkRed("FATAL"))
	log.ErrorAuto(format, a...)
	os.Exit(1)
}
