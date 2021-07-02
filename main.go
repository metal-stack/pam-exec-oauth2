// Copyright © 2017 Shinichi MOTOKI
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

const app = "pam-exec-oauth2"

type config struct {
	ClientID         string   `yaml:"client-id"`
	ClientSecret     string   `yaml:"client-secret"`
	RedirectURL      string   `yaml:"redirect-url"`
	Scopes           []string `yaml:"scopes"`
	EndpointAuthURL  string   `yaml:"endpoint-auth-url"`
	EndpointTokenURL string   `yaml:"endpoint-token-url"`
	UsernameFormat   string   `yaml:"username-format"`
}

func main() {
	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	exPath := filepath.Dir(ex)

	configFile := path.Join(exPath, app+".yaml")
	configFlg := flag.String("config", configFile, "config file to use")
	debug := false
	debugFlg := flag.Bool("debug", false, "enable debug")
	stdout := false
	stdoutFlg := flag.Bool("stdout", false, "log to stdout instead of syslog")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if stdoutFlg != nil {
		stdout = *stdoutFlg
	}

	sysLog, err := syslog.New(syslog.LOG_INFO, app)
	if err != nil {
		log.Fatal(err)
	}
	if !stdout {
		log.SetOutput(sysLog)
	}

	if debugFlg != nil {
		debug = *debugFlg
	}

	if configFlg != nil {
		log.Printf("using config file:%s", *configFlg)
		configFile = *configFlg
	}

	config, err := readConfig(configFile)
	if err != nil {
		log.Fatalf(err.Error())
	}
	if debug {
		log.Printf("config:%#v\n", config)
	}

	username := os.Getenv("PAM_USER")
	password := ""

	s := bufio.NewScanner(os.Stdin)
	if s.Scan() {
		password = s.Text()
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Scopes:       config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.EndpointAuthURL,
			TokenURL: config.EndpointTokenURL,
		},
		RedirectURL: config.RedirectURL,
	}
	oauth2Token, err := oauth2Config.PasswordCredentialsToken(
		context.Background(),
		fmt.Sprintf(config.UsernameFormat, username),
		password,
	)
	if err != nil {
		log.Fatal(err.Error())
	}

	if !oauth2Token.Valid() {
		log.Fatal("oauth2 authentication failed")
	}

	log.Print("oauth2 authentication succeeded")
	os.Exit(0)
}

func readConfig(filename string) (*config, error) {
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var c config
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal filecontent to config struct:%w", err)
	}
	return &c, nil
}
