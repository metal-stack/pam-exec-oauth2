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

// #include <security/pam_appl.h>
import "C"
import (
	"context"
	"regexp"
	"runtime"
	"strings"

	"fmt"
	"log/syslog"
	"os/exec"
	"os/user"

	"github.com/metal-stack/oauth2-login/internal/conf"

	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// app name
const app = "pam_oauth2"

func pamLog(format string, args ...interface{}) {
	l, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_WARNING, app)
	if err != nil {
		return
	}
	l.Warning(fmt.Sprintf(format, args...))
}

func pamAuthenticate(pamh *C.pam_handle_t, uid int, username string, argv []string) int {
	runtime.GOMAXPROCS(1)

	config, err := conf.ReadConfig()
	if err != nil {
		pamLog("Error reading config: %v", err)
		return PAM_OPEN_ERR
	}

	if len(config.NameRegex) > 0 {
		// Accept only for usernames that match the Regex
		if match, _ := regexp.MatchString(config.NameRegex, username); match == false {
			pamLog("username %s did not match 'name-regex'", username)
			return PAM_USER_UNKNOWN
		}
	}

	password := strings.TrimSpace(requestPass(pamh, C.PAM_PROMPT_ECHO_OFF, "oauth2-Password: "))

	// authentication agains oidc provider
	// load configuration from yaml config
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
	pamLog("call OIDC provider and get token")

	oauth2Token, err := oauth2Config.PasswordCredentialsToken(
		context.Background(),
		fmt.Sprintf(config.UsernameFormat, username),
		password,
	)
	if err != nil {
		pamLog("oauth2 authentication failed: %v", err)
		return PAM_AUTH_ERR
	}

	// check here is token vaild
	if !oauth2Token.Valid() {
		pamLog("oauth2 authentication failed")
		return PAM_AUTH_ERR
	}

	// check group for authentication is in token
	roles, err := validateClaims(oauth2Token.AccessToken, config.SufficientRoles)
	if err != nil {
		pamLog("error validate claims: %v", err)
		return PAM_AUTH_ERR
	}

	// Filter out all not allowed roles comming from OIDC
	groups := []string{}
	for _, r := range roles {
		for _, ar := range config.AllowedRoles {
			if r == ar {
				groups = append(groups, r)
			}
		}
	}
	if config.CreateUser {
		err = modifyUser(username, groups)
		if err != nil {
			pamLog("unable to add groups: %v", err)
			return PAM_AUTH_ERR
		}
	}

	pamLog("oauth2 authentication succeeded")
	return PAM_SUCCESS
}

// main is for testing purposes only, the PAM module has to be built with:
// go build -buildmode=c-shared
func main() {

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
					pamLog("validateClaims access granted role " + role + " is in token")
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
