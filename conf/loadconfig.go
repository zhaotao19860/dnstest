package conf

import (
	"encoding/json"
	"io/ioutil"
)

//Config for log and other
type Config struct {
	Basic *Basic
	Log   *Log
}

//Basic for basic config
type Basic struct {
	Cores        int
	TestCasePath string
	Servers      []string
}

//Log for log config
type Log struct {
	LogConfigFile string
	MinLevel      string
}

//LoadConfig for load config
func LoadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}
