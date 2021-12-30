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
	"os/exec"
	"os/user"

	"github.com/metal-stack/v"

	"github.com/metal-stack/oauth2-login/internal/conf"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// app name
const app = "pam-oauth2"

type pamOAUTH struct {
	config *conf.Config
}

// main primary entry
func main() {
	p, err := newPamOAUTH()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("version: %s", v.V)

	err = p.run()
	if err != nil {
		log.Fatal(err)
	}
}

func (p *pamOAUTH) run() error {
	// pam module use variable PAM_USER to get userid
	username := os.Getenv("PAM_USER")

	password := ""
	// wait for stdin to get password from user
	s := bufio.NewScanner(os.Stdin)
	if s.Scan() {
		password = s.Text()
	}

	// authentication agains oidc provider
	// load configuration from yaml config
	oauth2Config := oauth2.Config{
		ClientID:     p.config.ClientID,
		ClientSecret: p.config.ClientSecret,
		Scopes:       p.config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.config.EndpointAuthURL,
			TokenURL: p.config.EndpointTokenURL,
		},
		RedirectURL: p.config.RedirectURL,
	}

	// send authentication request to oidc provider
	log.Printf("call OIDC Provider and get token")

	oauth2Token, err := oauth2Config.PasswordCredentialsToken(
		context.Background(),
		fmt.Sprintf(p.config.UsernameFormat, username),
		password,
	)
	if err != nil {
		return err
	}

	// check here is token vaild
	if !oauth2Token.Valid() {
		return fmt.Errorf("oauth2 authentication failed")
	}

	// check group for authentication is in token
	roles, err := validateClaims(oauth2Token.AccessToken, p.config.SufficientRoles)
	if err != nil {
		return fmt.Errorf("error validate Claims: %w", err)
	}

	// Filter out all not allowed roles comming from OIDC
	groups := []string{}
	for _, r := range roles {
		for _, ar := range p.config.AllowedRoles {
			if r == ar {
				groups = append(groups, r)
			}
		}
	}
	if p.config.CreateUser {
		err = modifyUser(username, groups)
		if err != nil {
			return fmt.Errorf("unable to add groups: %w", err)
		}
	}

	log.Print("oauth2 authentication succeeded")
	return nil
}

func newPamOAUTH() (*pamOAUTH, error) {
	// initiate application parameters
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

	if !stdout {
		// initiate logging
		sysLog, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, app)
		if err != nil {
			return nil, err
		}
		log.SetOutput(sysLog)
	}

	if debugFlg != nil {
		debug = *debugFlg
	}

	config, err := conf.ReadConfig()
	if err != nil {
		return nil, err
	}
	if debug {
		log.Printf("config:%#v\n", config)
	}
	return &pamOAUTH{
		config: config,
	}, nil
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
	if len(sufficientRoles) > 0 {
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
	return claims.Roles, nil
}

// modifyUser add missing groups to the user
func modifyUser(username string, groups []string) error {
	_, err := user.Lookup(username)
	if err != nil && err.Error() != user.UnknownUserError(username).Error() {
		return fmt.Errorf("unable to lookup user %w", err)
	}

	if len(groups) > 0 {
		usermod, err := exec.LookPath("/usr/sbin/usermod")

		if err != nil {
			return fmt.Errorf("usermod command was not found %w", err)
		}

		args := []string{"-G"}
		args = append(args, groups...)
		args = append(args, username)
		cmd := exec.Command(usermod, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("unable to modify user output:%s %w", string(out), err)
		}
	}
	return nil
}
