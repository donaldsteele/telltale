/*
 * pam_lab.so: lab stand-in for a planted PAM module. It is referenced from the
 * PAM configuration, so the footprint is there, and it does nothing: every hook
 * returns PAM_IGNORE, so PAM carries on as if the module were not listed.
 * The constants are written out so no PAM headers are needed to build it.
 * Build: cc -shared -fPIC -O2 -o pam_lab.so pam_lab.c
 */
#define PAM_IGNORE 25

typedef struct pam_handle pam_handle_t;

#define HOOK(name) int name(pam_handle_t *h, int flags, int argc, const char **argv) { \
	(void)h; (void)flags; (void)argc; (void)argv; return PAM_IGNORE; }

HOOK(pam_sm_authenticate)
HOOK(pam_sm_setcred)
HOOK(pam_sm_acct_mgmt)
HOOK(pam_sm_open_session)
HOOK(pam_sm_close_session)
HOOK(pam_sm_chauthtok)
