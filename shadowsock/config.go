package shadowsock

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

type Config struct {
	ServerPort  int    `json:"server_port"`
	Password    string `json:"password"`
	Method      string `json:"method"`
	ReadTimeout int    `json:"timeout"`
}

var SsConfig = newConfig("./config.json")

func newConfig(path string) (config *Config) {
	file, err := os.Open(path)
	if err != nil {
		panic("open config.json failed: " + err.Error())
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
		return
	}

	config = &Config{}
	if err = json.Unmarshal(data, config); err != nil {
		panic("parse config.json failed: " + err.Error())
		return nil
	}

	return
}
