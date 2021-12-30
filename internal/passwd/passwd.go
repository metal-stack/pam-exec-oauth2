// Most of this code was taken from https://github.com/glestaris/passwduser

package passwd

import (
	"bufio"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// User represents a user account.
type User struct {
	UID     uint // user ID
	GID     uint // primary group ID
	Name    string
	Gecos   string
	Shell   string
	HomeDir string
}

var passwdFilePath = "/etc/passwd"

// Lookup finds a user by her username.
func Lookup(username string) (*User, error) {
	passwdFile, err := os.Open(passwdFilePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = passwdFile.Close()
	}()

	users, err := parsePasswdFilter(passwdFile, func(u User) bool {
		return u.Name == username
	})
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, user.UnknownUserError(username)
	}

	return &users[0], nil
}

func parseLine(line string) User {
	user := User{}

	// see: man 5 passwd
	//  name:password:UID:GID:GECOS:directory:shell
	parts := strings.Split(line, ":")
	if len(parts) >= 1 {
		user.Name = parts[0]
	}
	if len(parts) >= 3 {
		uid, _ := strconv.ParseUint(parts[2], 10, 0)
		user.UID = uint(uid)
	}
	if len(parts) >= 4 {
		gid, _ := strconv.ParseUint(parts[3], 10, 0)
		user.GID = uint(gid)
	}
	if len(parts) >= 5 {
		user.Gecos = parts[4]
	}
	if len(parts) >= 6 {
		user.HomeDir = parts[5]
	}
	if len(parts) >= 7 {
		user.Shell = parts[6]
	}

	return user
}

func parsePasswdFilter(r io.Reader, filter func(User) bool) ([]User, error) {
	out := []User{}

	s := bufio.NewScanner(r)
	for s.Scan() {
		if err := s.Err(); err != nil {
			return nil, err
		}

		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		p := parseLine(line)
		if filter == nil || filter(p) {
			out = append(out, p)
		}
	}

	return out, nil
}
