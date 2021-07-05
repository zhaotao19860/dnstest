package log

import (
	"time"

	"github.com/cihub/seelog"
)

const (
	LevelNone = iota
	LevelCritical
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

var logLevel int = LevelTrace

// Tracef formats message according to format specifier
// and writes to default logger with log level = Trace.
func Tracef(format string, params ...interface{}) {
	if logLevel < LevelTrace {
		return
	}
	seelog.Tracef(format, params...)
}

// Debugf formats message according to format specifier
// and writes to default logger with log level = Debug.
func Debugf(format string, params ...interface{}) {
	if logLevel < LevelDebug {
		return
	}
	seelog.Debugf(format, params...)
}

// Infof formats message according to format specifier
// and writes to default logger with log level = Info.
func Infof(format string, params ...interface{}) {
	if logLevel < LevelInfo {
		return
	}
	seelog.Infof(format, params...)
}

// Warnf formats message according to format specifier and writes to default logger with log level = Warn
func Warnf(format string, params ...interface{}) error {
	if logLevel < LevelWarn {
		return nil
	}
	seelog.Warnf(format, params...)
	return nil
}

// Errorf formats message according to format specifier and writes to default logger with log level = Error
func Errorf(format string, params ...interface{}) error {
	if logLevel < LevelError {
		return nil
	}
	seelog.Errorf(format, params...)
	return nil
}

// Criticalf formats message according to format specifier and writes to default logger with log level = Critical
func Criticalf(format string, params ...interface{}) error {
	if logLevel < LevelCritical {
		return nil
	}
	seelog.Criticalf(format, params...)
	return nil
}

// Trace formats message using the default formats for its operands and writes to default logger with log level = Trace
func Trace(v ...interface{}) {
	if logLevel < LevelTrace {
		return
	}
	seelog.Trace(v...)
}

// Debug formats message using the default formats for its operands and writes to default logger with log level = Debug
func Debug(v ...interface{}) {
	if logLevel < LevelDebug {
		return
	}
	seelog.Debug(v...)
}

// Info formats message using the default formats for its operands and writes to default logger with log level = Info
func Info(v ...interface{}) {
	if logLevel < LevelInfo {
		return
	}
	seelog.Info(v...)
}

// Warn formats message using the default formats for its operands and writes to default logger with log level = Warn
func Warn(v ...interface{}) error {
	if logLevel < LevelWarn {
		return nil
	}
	seelog.Warn(v...)
	return nil
}

// Error formats message using the default formats for its operands and writes to default logger with log level = Error
func Error(v ...interface{}) error {
	if logLevel < LevelError {
		return nil
	}
	seelog.Error(v...)
	return nil
}

// Critical formats message using the default formats for its operands and writes to default logger with log level = Critical
func Critical(v ...interface{}) error {
	if logLevel < LevelCritical {
		return nil
	}
	seelog.Critical(v...)
	return nil
}

func Flush() {
	seelog.Flush()
}

func Current() seelog.LoggerInterface {
	return seelog.Current
}

func LoggerFromConfigAsFile(fileName string) (seelog.LoggerInterface, error) {
	return seelog.LoggerFromConfigAsFile(fileName)
}

func ReplaceLogger(logger seelog.LoggerInterface) error {
	logger.SetAdditionalStackDepth(1)
	return seelog.ReplaceLogger(logger)
}

func Init(fileName string, lv int, flushEverySec int) error {
	logger, err := LoggerFromConfigAsFile(fileName)
	if err != nil {
		return err
	}
	logLevel = lv
	err = ReplaceLogger(logger)
	if err != nil {
		return err
	}

	if flushEverySec != 0 {
		go func() {
			for {
				time.Sleep(time.Duration(flushEverySec) * time.Second)
				seelog.Flush()
			}
		}()
	}
	return nil
}

func LogLevel(lv string) int {
	switch lv {
	case "cri", "critical", "Cri", "Critical":
		return LevelCritical
	case "err", "error", "Err", "Error":
		return LevelError
	case "warn", "Warn":
		return LevelWarn
	case "inf", "info", "Inf", "Info":
		return LevelInfo
	case "debug", "Debug":
		return LevelDebug
	case "trace", "Trace":
		return LevelTrace
	}

	return LevelWarn
}
