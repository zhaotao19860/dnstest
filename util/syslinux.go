package util

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SetRlimitNOFILE set the max open files.
func SetRlimitNOFILE() (err error) {
	var rlim unix.Rlimit
	err = unix.Getrlimit(unix.RLIMIT_NOFILE, &rlim)
	if err != nil {
		fmt.Println("get rlimit error: " + err.Error())
		return err
	}
	rlim.Cur = 50000
	rlim.Max = 50000
	err = unix.Setrlimit(unix.RLIMIT_NOFILE, &rlim)
	if err != nil {
		fmt.Println("set rlimit error: " + err.Error())
		return err
	}
	return
}
