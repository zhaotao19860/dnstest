package main

import (
	"flag"
	"fmt"
	"runtime"
	"sync"

	"github.com/zhaotao19860/dnstest/conf"
	"github.com/zhaotao19860/dnstest/dig"
	"github.com/zhaotao19860/dnstest/log"
	"github.com/zhaotao19860/dnstest/util"
)

func initLog(cfgFile string, minLevel string) error {
	return log.Init(cfgFile, log.LogLevel(minLevel), 0)
}

func main() {
	totalNum := 0

	configPath := flag.String("c", "./etc/config.json", "config file name")
	digOnce := flag.Bool("once", false, "dig a domain once")
	port := flag.Uint("p", 53, "port")
	flag.Parse()
	args := flag.Args()

	if *digOnce && len(args) > 1 {
		dig.DigOneShot(uint16(*port), args)
		return
	}

	config, err := conf.LoadConfig(*configPath)
	if err != nil {
		fmt.Printf("load config[%v] failed, error[%v]\n", *configPath, err)
		return
	}

	runtime.GOMAXPROCS(config.Basic.Cores)

	err = initLog(config.Log.LogConfigFile, config.Log.MinLevel)
	if err != nil {
		fmt.Printf("init log error, err[%v]\n", err)
		return
	}

	err = util.SetRlimitNOFILE()
	if err != nil {
		return
	}

	testcase := conf.LoadCSV(config.Basic.TestCasePath)
	if testcase == nil {
		log.Flush()
		return
	}
	goroutineWaitGroup := sync.WaitGroup{} //构建一个waitGroup
	for _, server := range config.Basic.Servers {
		for _, v := range testcase.Case {
			goroutineWaitGroup.Add(1)
			//每个目的server+每个case启动一个goroutine
			go dig.DNSCheck(&goroutineWaitGroup, v, server)
			totalNum++
		}
	}
	goroutineWaitGroup.Wait()
	log.Infof("TEST COMPLETE: TOTAL:[%v] SUCCEEDED:[%v] FAILED:[%v]\n",
		totalNum, dig.SucceededNum, dig.FailedNum)
	log.Flush()
	fmt.Printf("TEST COMPLETE: TOTAL:[%v] SUCCEEDED:[%v] FAILED:[%v]\n",
		totalNum, dig.SucceededNum, dig.FailedNum)
}
