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
	"os"

	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

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
	configFile := "pam-exec-oauth2.yaml"
	configFlg := flag.String("config", configFile, "config file to use")
	debugFlg := flag.Bool("debug", false, "enable debug")

	flag.Parse()

	if configFlg != nil {
		fmt.Println("using config file:", *configFlg)
		configFile = *configFlg
	}

	config, err := readConfig(configFile)
	if err != nil {
		panic(err)
	}
	if debugFlg != nil && *debugFlg {
		fmt.Printf("config:%#v\n", config)
	}

	username := os.Getenv("PAM_USER")
	password := ""

	stdinScanner := bufio.NewScanner(os.Stdin)
	if stdinScanner.Scan() {
		password = stdinScanner.Text()
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
	oauth2Context := context.Background()

	oauth2Token, err := oauth2Config.PasswordCredentialsToken(
		oauth2Context,
		fmt.Sprintf(config.UsernameFormat, username),
		password,
	)

	if err != nil {
		panic(err)
	}

	if !oauth2Token.Valid() {
		os.Exit(1)
		fmt.Println("oauth2 authentication failed")
	}

	fmt.Println("oauth2 authentication success")
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
