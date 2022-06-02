package main

import (
	"fmt"
	"io/ioutil"
	"sync"

	yaml "gopkg.in/yaml.v2"
)


type SafeConfig struct {
	sync.RWMutex
	C *HostConfig
}

type HostConfig struct {
	Host string `yaml:"host"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (sc *SafeConfig) ReloadConfig(configFile string) error {
	var c = &HostConfig{}

	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(yamlFile, c); err != nil {
		return err
	}

	sc.Lock()
	sc.C = c
	sc.Unlock()

	return nil
}

func (sc *SafeConfig) HostConfig() (*HostConfig, error) {
	sc.Lock()
	defer sc.Unlock()

	if hostConfig := sc.C; hostConfig != nil {
		return &HostConfig{
			Host: hostConfig.Host,
			Username: hostConfig.Username,
			Password: hostConfig.Password,
		}, nil
	}
	return &HostConfig{}, fmt.Errorf("no credentials found")
}
