package identity

import "testing"

func TestNativeIdentityRejectsProtectedAndUnsafeValues(t *testing.T) {
	valid := User{Login: "engineer", UID: 10001, GID: 10001, Home: "/home/engineer", Shell: "/bin/bash", GECOS: "Engineer"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*User){
		"root":                 func(u *User) { u.Login = "root" },
		"option injection":     func(u *User) { u.Login = "--root" },
		"privileged UID":       func(u *User) { u.UID = 0 },
		"reserved GID":         func(u *User) { u.GID = 998 },
		"path traversal":       func(u *User) { u.Home = "/home/../root" },
		"nested home":          func(u *User) { u.Home = "/home/engineer/.ssh" },
		"passwd injection":     func(u *User) { u.GECOS = "Engineer\nroot:x:0:0" },
		"arbitrary executable": func(u *User) { u.Shell = "/tmp/shell" },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			u := valid
			modify(&u)
			if u.Validate() == nil {
				t.Fatal("unsafe native identity accepted")
			}
		})
	}
}
