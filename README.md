# pam-exec-oauth2

## Install

```bash
make

sudo make install
```

## Configuration

### PAM

add the following lines to `/etc/pam.d/common-auth`

```
#### authenticate on login #####
auth sufficient pam_exec.so expose_authtok /sbin/pam-exec-oauth2
```

### NSS

add `oauth2` to the `passwd:` line in `/etc/nsswitch.conf` like this:

```
# /etc/nsswitch.conf

passwd:         files systemd oauth2
```

### pam-exec-oauth2.yaml

Configuration must be stored in `/etc/oauth2-login.config`. There is no option to change the location
of this config file. Examples:

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
sufficient-roles: 
    - "serverAccess"
allowed-roles: 
    - "wheel"
name-regex: "test.*"
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
sufficient-roles: 
    - "serverAccess"
allowed-roles: 
    - "wheel"
name-regex: "test.*"
```

#### Config options

- `createuser`: Enable user account autocreation.
- `name-regex`: Only logins that match the regex are allowed/created.
- `sufficient-roles`: User must have these roles assigned to login.
- `allowed-roles`: If a user has these roles, they will be assigned to his Unix user as groups.
  All other roles will be ignored.
