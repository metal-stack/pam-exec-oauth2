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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tredoe/osutil/user"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
	"gopkg.in/yaml.v2"
)

// app name
const app = "pam-exec-oauth2"

// config define openid Connect parameters
// and setting for this modul
type config struct {
	ClientID          string   `yaml:"client-id"`
	ClientSecret      string   `yaml:"client-secret"`
	RedirectURL       string   `yaml:"redirect-url"`
	Scopes            []string `yaml:"scopes"`
	EndpointAuthURL   string   `yaml:"endpoint-auth-url"`
	EndpointTokenURL  string   `yaml:"endpoint-token-url"`
	UsernameFormat    string   `yaml:"username-format"`
	SufficientRoles   []string `yaml:"sufficient-roles"`
	CreateUser        bool     `yaml:"createuser"`
	CreateGroup       bool     `yaml:"creategroup"`
	CreateGroupMember bool     `yaml:"creategroupmember"`
	DeleteOidcUsers   bool     `yaml:"delete-oidc-users"`
	DeleteUserDays    int      `yaml:"delete-users-days"`
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

	// add user here only if user is in passwd the login worked
	if config.CreateUser {
		createUser(username)
	}

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
	err = validateClaims(oauth2Token.AccessToken, config.SufficientRoles, username, config.CreateGroup, config.CreateGroupMember)
	if err != nil {
		log.Fatal(err.Error())
	}

	if config.DeleteOidcUsers {
		deleteOldUser(*config)
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

// myClain define token struct
type myClaim struct {
	jwt.Claims
	Roles []string `json:"roles,omitempty"`
}

// validateClaims check role fom config sufficetRoles is in token roles claim
func validateClaims(t string, sufficientRoles []string, username string, addGroup bool, addmembership bool) error {
	token, err := jwt.ParseSigned(t)
	if err != nil {
		return fmt.Errorf("error parsing token: %w", err)
	}

	claims := myClaim{}
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return fmt.Errorf("unable to extract claims from token: %w", err)
	}
	for _, role := range claims.Roles {

		if addGroup {
			createGroup(role, username)
		}

		if addmembership {
			addUserToGroup(role, username)
		}

		for _, sr := range sufficientRoles {
			if role == sr {
				log.Print("validateClaims access granted role " + role + " is in token")
				return nil
			}
		}
	}
	return fmt.Errorf("role: %s not found", sufficientRoles)
}

// createUser this create user is not exsits
func createUser(username string) {
	_, err := user.LookupUser(username)

	var pathError *user.NoFoundError
	// if no user then add one
	if ok := errors.As(err, &pathError); ok {

		cmd := exec.Command("usr/sbin/useradd", "-m", "-s", "/bin/bash", "-c", app, username)
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("user already exists: %s ", err.Error())
		}

		log.Printf("%s", stdoutStderr)
	} else {
		log.Printf("user already exists: %s skip create", username)
	}
}

// getLastLogin for a user
func getLastLogin(username string) time.Time {

	cmd := exec.Command("last", "-1", username)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("No lastlogin: %s ", err.Error())
	}

	s := string(stdoutStderr)
	split := strings.Split(s, " ")
	x := strings.TrimSpace(split[2] + " " + split[3] + " " + split[4] + " " + split[5] + " " + split[6] + " " + split[7])
	return parseloginTime(x)
}

// parseloginTime get time from pased last command
func parseloginTime(currenttime string) time.Time {

	layout := time.ANSIC
	t, err := time.Parse(layout, currenttime)

	if err != nil {
		fmt.Println(err)
	}
	return t
}

// createUser this create user is not exsits
func createGroup(role string, username string) {
	_, err := user.LookupGroup(role)
	var pathError *user.NoFoundError
	// if no group then add one
	if ok := errors.As(err, &pathError); ok {

		gid, err := user.AddGroup(role, username)

		if err != nil {
			log.Printf("cannot create group :%s ", err.Error())
		}

		log.Print("group: " + role + " created gid: " + strconv.Itoa(gid))

	} else {
		log.Printf("group already exists: %s skip set member", username)
	}
}

// addUserToGroup add user to group by roles
func addUserToGroup(role string, username string) {
	_, err := user.LookupGroup(role)
	var pathError *user.NoFoundError
	// if no group then add one
	if ok := errors.As(err, &pathError); ok {

		err := user.AddUsersToGroup(role, username)

		if err != nil {
			log.Printf("cannot create membership :%s ", err.Error())
		}
		log.Printf("user added to :%s ", role)
	}
}

// getAllUsers list all users from passwd
func getAllUsers() []string {

	var Users []string
	file, err := os.Open("/etc/passwd")

	if err != nil {
		fmt.Println(err)
	}

	defer file.Close()

	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')

		// skip all line starting with #
		if equal := strings.Index(line, "#"); equal < 0 {
			// get the username and description
			lineSlice := strings.FieldsFunc(line, func(divide rune) bool {
				return divide == ':' // we divide at colon
			})

			if len(lineSlice) > 0 {
				Users = append(Users, lineSlice[0])
			}

		}

		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println(err)
		}

	}
	return Users
}

// deleteOldUsers from added by pam modul
func deleteOldUser(c config) {

	for _, u := range getAllUsers() {

		currentuser, err := user.LookupUser(u)
		if err != nil {
			log.Printf("user not found :%s ", err.Error())
		}

		// check user is added from modul and login since  days
		if currentuser.Gecos == app && getLastLogin(u).Before(time.Now().AddDate(0, 0, -c.DeleteUserDays)) {
			log.Printf("user added from modul and no login since config days")
			err := user.DelUser(u)
			if err != nil {
				log.Printf("user not deleted :%s ", err.Error())
			}
		}
	}
}
