package main

import (
	"unsafe"
)

/*
#cgo LDFLAGS: -lpam -fPIC
#include <security/pam_appl.h>
#include <stdlib.h>
char *string_from_argv(int, char**);
char *get_user(pam_handle_t *pamh);
int get_uid(char *user);
int change_euid(int);
int disable_ptrace();
char *request_pass(pam_handle_t *, int, const char *);
*/
import "C"

const (
	PAM_OPEN_ERR     = C.PAM_OPEN_ERR
	PAM_USER_UNKNOWN = C.PAM_USER_UNKNOWN
	PAM_AUTH_ERR     = C.PAM_AUTH_ERR
	PAM_SUCCESS      = C.PAM_SUCCESS
)

func init() {
	if !disablePtrace() {
		pamLog("unable to disable ptrace")
	}
}

func sliceFromArgv(argc C.int, argv **C.char) []string {
	r := make([]string, 0, argc)
	for i := 0; i < int(argc); i++ {
		s := C.string_from_argv(C.int(i), argv)
		defer C.free(unsafe.Pointer(s))
		r = append(r, C.GoString(s))
	}
	return r
}

//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	cUsername := C.get_user(pamh)
	if cUsername == nil {
		return C.PAM_USER_UNKNOWN
	}
	defer C.free(unsafe.Pointer(cUsername))

	uid := int(C.get_uid(cUsername))
	if uid < 0 {
		return C.PAM_USER_UNKNOWN
	}

	r := pamAuthenticate(pamh, uid, C.GoString(cUsername), sliceFromArgv(argc, argv))
	return C.int(r)
}

//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	return C.PAM_SUCCESS
}

func seteuid(uid int) bool {
	return C.change_euid(C.int(uid)) == C.int(0)
}

func disablePtrace() bool {
	return C.disable_ptrace() == C.int(0)
}

func requestPass(pamh *C.pam_handle_t, echocode int, prompt string) string {
	cprompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cprompt))
	v := C.request_pass(pamh, C.int(echocode), cprompt)
	defer C.free(unsafe.Pointer(v))
	ret := C.GoString(v)
	return ret
}

func getUser(pamh *C.pam_handle_t) string {
	cUsername := C.get_user(pamh)
	defer C.free(unsafe.Pointer(cUsername))

	ret := C.GoString(cUsername)
	return ret
}
