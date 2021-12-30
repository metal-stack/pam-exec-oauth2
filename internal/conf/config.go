package conf

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

const configFile = "/etc/oauth2-login.conf"

// config define openid Connect parameters
// and setting for this module
type Config struct {
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
	NameRegex    string   `yaml:"name-regex"`
}

// ReadConfig
// need file path from yaml and return config
func ReadConfig() (*Config, error) {
	yamlFile, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	var c Config
	err = yaml.Unmarshal(yamlFile, &c)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal filecontent to config struct:%w", err)
	}
	return &c, nil
}
