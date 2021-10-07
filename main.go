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
	"strings"

	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
	"gopkg.in/yaml.v2"
)

// app name
const app = "pam-exec-oauth2"

// config define openid Connect parameters
// and setting for this module
type config struct {
	ClientID         string   `yaml:"client-id"`
	ClientSecret     string   `yaml:"client-secret"`
	RedirectURL      string   `yaml:"redirect-url"`
	Scopes           []string `yaml:"scopes"`
	EndpointAuthURL  string   `yaml:"endpoint-auth-url"`
	EndpointTokenURL string   `yaml:"endpoint-token-url"`
	UsernameFormat   string   `yaml:"username-format"`
	SufficientRoles  []string `yaml:"sufficient-roles"`
	// AllowedRoles are OS level groups which must be present on the OS before
	AllowedRoles []string `yaml:"allowed-roles"`
	CreateUser   bool     `yaml:"createuser"`
}

// main primary entry
func main() {

	// get executable and path name
	// to determine the default config file
	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	exPath := filepath.Dir(ex)

	// initiate application parameters
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

	// initiate logging
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

	// pam modul use variable PAM_USER to get userid
	username := os.Getenv("PAM_USER")

	password := ""
	// wait for stdin to get password from user
	s := bufio.NewScanner(os.Stdin)
	if s.Scan() {
		password = s.Text()
	}

	// authentication agains oidc provider
	// load configuration from yaml config
	log.Print("Load Config OpenID Modul ")
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

	// send authentication request to oidc provider
	log.Print("Call OIDC Provider and get Token")

	oauth2Token, err := oauth2Config.PasswordCredentialsToken(
		context.Background(),
		fmt.Sprintf(config.UsernameFormat, username),
		password,
	)

	if err != nil {
		log.Fatal(err.Error())
	}

	// check here is token vaild
	if !oauth2Token.Valid() {
		log.Fatal("oauth2 authentication failed")
	}

	// check group for authentication is in token
	roles, err := validateClaims(oauth2Token.AccessToken, config.SufficientRoles)
	if err != nil {
		log.Fatalf("error validate Claims: %s", err)
	}

	// Filter out all not allowed roles comming from OIDC
	osRoles := []string{}
	for _, r := range roles {
		for _, ar := range config.AllowedRoles {
			if r == ar {
				osRoles = append(osRoles, r)
			}
		}
	}

	// add user here only if user is in passwd the login worked
	if config.CreateUser {
		err := createUser(username, osRoles)
		if err != nil {
			log.Fatal(err.Error())
		}
	}

	log.Print("oauth2 authentication succeeded")
	os.Exit(0)
}

// readConfig
// need file path from yaml and return config
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

// myClaim define token struct
type myClaim struct {
	jwt.Claims
	Roles []string `json:"roles,omitempty"`
}

// validateClaims check role fom config sufficientRoles is in token roles claim
func validateClaims(t string, sufficientRoles []string) ([]string, error) {
	token, err := jwt.ParseSigned(t)
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	claims := myClaim{}
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("unable to extract claims from token: %w", err)
	}
	for _, role := range claims.Roles {
		for _, sr := range sufficientRoles {
			if role == sr {
				log.Print("validateClaims access granted role " + role + " is in token")
				return claims.Roles, nil
			}
		}
	}
	return nil, fmt.Errorf("role: %s not found", sufficientRoles)
}

// createUser if it does not already exists
func createUser(username string, roles []string) error {
	_, err := user.Lookup(username)
	if err != nil && err.Error() != user.UnknownUserError(username).Error() {
		return fmt.Errorf("unable to lookup user %w", err)
	}

	if err == nil {
		log.Printf("user %s already exists\n", username)
		return nil
	}

	useradd, err := exec.LookPath("/usr/sbin/useradd")

	if err != nil {
		return fmt.Errorf("useradd command was not found %w", err)
	}

	args := []string{"-m", "-s", "/bin/bash", "-c", app, username}
	if len(roles) > 0 {
		args = append(args, "-G", strings.Join(roles, " "))
	}

	cmd := exec.Command(useradd, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to create user output:%s %w", string(out), err)
	}
	return nil
}
