# pam-exec-oauth2

## Install

```bash
go get github.com/shimt/pam-exec-oauth2

PREFIX=/opt/pam-exec-oauth2

sudo mkdir $PREFIX
sudo cp go/bin/pam-exec-oauth2 $PREFIX/pam-exec-oauth2
sudo touch $PREFIX/pam-exec-oauth2.yaml
sudo chmod 755 $PREFIX/pam-exec-oauth2
sudo chmod 600 $PREFIX/pam-exec-oauth2.yaml
```

## Configuration

### PAM

add the following lines to `/etc/pam.d/common-auth`

```bash
#### create user and authenticate on login #####
auth sufficient pam_exec.so expose_authtok /opt/pam-exec-oauth2/pam-exec-oauth2
```

add the following lines to `/etc/pam.d/common-session`

```bash
#### remove user on logout #####
session     optional    pam_exec.so quiet /opt/pam-exec-oauth2/pam-exec-oauth2
```

### pam-exec-oauth2.yaml

edit `/opt/pam-exec-oauth2/pam-exec-oauth2.yaml`

#### Azure AD

```yaml
---
client-id: "xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client-secret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
redirect-url: "urn:ietf:wg:oauth:2.0:oob"
scopes: 
    - "email"
endpoint-auth-url: "https://login.windows.net/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/authorize"
endpoint-token-url: "https://login.windows.net/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/token"
username-format: "%s@example.org"
createuser: true
creategroup: true
creategroupmember: true
delete-oidc-users: true
delete-users-days: 30
```

#### Keycloak

```yaml
---
client-id: "xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
client-secret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
redirect-url: "urn:ietf:wg:oauth:2.0:oob"
scopes: 
    - "email"
endpoint-auth-url: "https://%host%/auth/realms/%yourrealm%/protocol/openid-connect/auth"
endpoint-token-url: "https://%host%/auth/realms/%yourrealm%/protocol/openid-connect/token"
username-format: "%s"
createuser: true
creategroup: true
creategroupmember: true
delete-oidc-users: true
delete-users-days: 30
```
