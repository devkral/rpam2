#include "ruby.h"
#include <string.h>

#ifndef WITHOUT_PAM_HEADER
#include <security/pam_appl.h>
#else
/* status */
#define PAM_SUCCESS 0
#define PAM_BUF_ERR 5
#define PAM_CONV_ERR 19

/* items */
#define PAM_SERVICE 1
#define PAM_CONV 5
#define PAM_RHOST 4
#define PAM_RUSER 8

/* Messages */
#define PAM_PROMPT_ECHO_OFF 1
#define PAM_PROMPT_ECHO_ON 2
#define PAM_ERROR_MSG 3
#define PAM_TEXT_INFO 4

typedef struct pam_handle pam_handle_t;


struct pam_message {
    int msg_style;
    const char *msg;
};

struct pam_response {
    char *resp;
    int	resp_retcode;	/* currently un-used, zero expected */
};

/* The actual conversation structure itself */

struct pam_conv {
    int (*conv)(int num_msg, const struct pam_message **msg,
		struct pam_response **resp, void *appdata_ptr);
    void *appdata_ptr;
};

// fix implicit function warnings:

int pam_start(const char *service_name, const char *user, const struct pam_conv *pam_conversation, pam_handle_t **pamh);
int pam_end(pam_handle_t *pamh, int pam_status);

int pam_authenticate(pam_handle_t *pamh, int flags);
int pam_acct_mgmt(pam_handle_t *pamh, int flags);
const char *pam_strerror(pam_handle_t *pamh, int errnum);
int pam_set_item(pam_handle_t *pamh, int item_type, const void *item);
int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item);
char **pam_getenvlist(pam_handle_t *pamh);
const char *pam_getenv(pam_handle_t *pamh, const char *name);

int pam_open_session(pam_handle_t *pamh, int flags);
int pam_close_session(pam_handle_t *pamh, int flags);

#endif



static const char *const
rpam_default_servicename = "rpam";

struct auth_wrapper{
  char* pw;
};

VALUE rpam2;

int rpam_auth_conversation(int num_msg, const struct pam_message **msgm,
                           struct pam_response **resp, void *appdata_ptr){
    struct auth_wrapper *authw = (struct auth_wrapper *)appdata_ptr;
    struct pam_response *responses = calloc(num_msg, sizeof(struct pam_response));
    /* no space for responses*/
    if (!responses)
        return PAM_BUF_ERR;
    for (int msgc=0; msgc<num_msg; msgc++){
        switch (msgm[msgc]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                /* Assume ECHO_OFF is password/secret input */
                responses[msgc].resp = strdup(authw->pw);
                break;
            case PAM_PROMPT_ECHO_ON:
            case PAM_TEXT_INFO:
                /* ignore, they should not occur but some verbose applications exist always */
                responses[msgc].resp = strdup("");
                break;
            case PAM_ERROR_MSG:
                /* print error message */
                rb_warn("%s", msgm[msgc]->msg);
                responses[msgc].resp = strdup("");
                break;
            default:
                free(responses);
                return PAM_CONV_ERR;
        }
        /* response could not be allocated (no space) */
        if(responses[msgc].resp==0){
            free(responses);
            return PAM_BUF_ERR;
        }
    }
    *resp = responses;
    return PAM_SUCCESS;
}

// password as char* ensures that no Qnil can be used
static unsigned int _start(pam_handle_t* pamh, VALUE* service, char* password, VALUE *RUSER, VALUE* RHOST){
    struct pam_conv auth_c;
    struct auth_wrapper authw;
    unsigned int result = 0;

    if(service && !NIL_P(*service)){
        result = pam_set_item(pamh, PAM_SERVICE, StringValueCStr(*service));

        if (result != PAM_SUCCESS) {
            rb_warn("SET SERVICE: %s", pam_strerror(pamh, result));
            return result;
        }
    }

    if(RUSER && !NIL_P(*RUSER)){
        result = pam_set_item(pamh, PAM_RUSER, StringValueCStr(*RUSER));
        if (result != PAM_SUCCESS) {
            rb_warn("SET RUSER: %s", pam_strerror(pamh, result));
            return result;
        }
    }

    if(RHOST && !NIL_P(*RHOST)){
        result = pam_set_item(pamh, PAM_RHOST, StringValueCStr(*RHOST));
        if (result != PAM_SUCCESS) {
            rb_warn("SET RHOST: %s", pam_strerror(pamh, result));
            return result;
        }
    }

    result = pam_acct_mgmt(pamh, 0);
    if (result != PAM_SUCCESS) {
        pam_end(pamh, result);
        return result;
    }

    if(password){
        // cannot set token as item (except implementing some special methods) so use a conversation
        auth_c.conv = rpam_auth_conversation;
        authw.pw = password;
        auth_c.appdata_ptr = &authw;

        result = pam_set_item(pamh, PAM_CONV, &auth_c);
        if (result != PAM_SUCCESS) {
            rb_warn("SET CONV: %s", pam_strerror(pamh, result));
            return result;
        }
        result = pam_authenticate(pamh, 0);
        if (result != PAM_SUCCESS) {
            pam_end(pamh, result);
            return result;
        }
    }
    return result;
}


static VALUE method_authpam(VALUE self, VALUE servicename, VALUE username, VALUE password, VALUE ruser, VALUE rhost) {
     pam_handle_t* pamh = NULL;
    unsigned int result = 0;
    struct pam_conv auth_c = {0,0};

    Check_Type(username, T_STRING);
    Check_Type(password, T_STRING);

    result = pam_start(rpam_default_servicename, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("INIT: %s", pam_strerror(pamh, result));
        return Qfalse;
    }

    result = _start(pamh, &servicename, StringValueCStr(password), &ruser, &rhost);
    if(result!=PAM_SUCCESS)
        return Qfalse;


    if (pam_end(pamh, result) == PAM_SUCCESS)
        return Qtrue;
    else {
        rb_warn("END: %s", pam_strerror(pamh, result));
        return Qfalse;
    }
}


static VALUE method_accountpam(VALUE self, VALUE servicename, VALUE username) {
    pam_handle_t* pamh = NULL;
    unsigned int result=0;
    struct pam_conv auth_c = {0,0};

    Check_Type(username, T_STRING);

    result = pam_start(rpam_default_servicename, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("INIT: %s", pam_strerror(pamh, result));
        return Qfalse;
    }

    result = _start(pamh, &servicename, NULL, NULL, NULL);
    if(result!=PAM_SUCCESS)
        return Qfalse;

    if (pam_end(pamh, result) == PAM_SUCCESS)
        return Qtrue;
    else {
        rb_warn("END: %s", pam_strerror(pamh, result));
        return Qfalse;
    }
}


static VALUE method_getenvpam(VALUE self, VALUE servicename, VALUE username, VALUE password, VALUE envname, VALUE opensession, VALUE ruser, VALUE rhost) {
    pam_handle_t* pamh = NULL;
    const char *c_ret=NULL;
    VALUE ruby_ret;
    unsigned int result = 0;
    struct pam_conv auth_c = {0,0};

    Check_Type(username, T_STRING);
    Check_Type(password, T_STRING);
    Check_Type(envname, T_STRING);

    result = pam_start(rpam_default_servicename, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("INIT: %s", pam_strerror(pamh, result));
        return Qnil;
    }

    result = _start(pamh, &servicename, StringValueCStr(password), &ruser, &rhost);
    if(result != PAM_SUCCESS)
        return Qnil;

    if (RTEST(opensession)){
        result = pam_open_session(pamh, 0);
        if (result != PAM_SUCCESS) {
            rb_warn("SESSION OPEN: %s", pam_strerror(pamh, result));
            pam_end(pamh, result);
            return Qnil;
        }
    }
    c_ret = pam_getenv(pamh, StringValueCStr(envname));
    if(c_ret){
        ruby_ret = rb_str_new_cstr(c_ret);
    } else {
        ruby_ret = Qnil;
    }

    if (RTEST(opensession)){
        result = pam_close_session(pamh, 0);
        if (result != PAM_SUCCESS) {
            rb_warn("SESSION END: %s", pam_strerror(pamh, result));
        }
    }

    result = pam_end(pamh, result);
    if (result != PAM_SUCCESS) {
        rb_warn("END: %s", pam_strerror(pamh, result));
    }
    return ruby_ret;
}


static VALUE method_listenvpam(VALUE self, VALUE servicename, VALUE username, VALUE password, VALUE opensession, VALUE ruser, VALUE rhost){
    pam_handle_t* pamh = NULL;
    unsigned int result=0;
    char *last=NULL;
    char **envlist=NULL;
    char **tmpenvlist=NULL;
    VALUE ruby_ret;
    struct pam_conv auth_c = {0,0};

    Check_Type(username, T_STRING);
    Check_Type(password, T_STRING);


    result = pam_start(rpam_default_servicename, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("INIT: %s", pam_strerror(pamh, result));
        return Qnil;
    }

    result = _start(pamh, &servicename, StringValueCStr(password), &ruser, &rhost);
    if(result != PAM_SUCCESS)
        return Qnil;

    if (RTEST(opensession)){
        result = pam_open_session(pamh, 0);
        if (result != PAM_SUCCESS) {
            rb_warn("SESSION OPEN: %s", pam_strerror(pamh, result));
            pam_end(pamh, result);
            return Qnil;
        }
    }

    envlist = pam_getenvlist(pamh);
    ruby_ret = rb_hash_new();
    tmpenvlist = envlist;
    while(*tmpenvlist!=NULL){
        last = strchr(*tmpenvlist, '=');
        /* should not be needed but better be safe in a security relevant application */
        if (last!=NULL){
            rb_hash_aset(ruby_ret, rb_str_new(*tmpenvlist, last-*tmpenvlist), rb_str_new_cstr(last+1));
        }
        /* strings have to be freed (specification)
         overwrite them with zero to prevent leakage */
        memset(*tmpenvlist, 0, strlen(*tmpenvlist));
        free(*tmpenvlist);
        tmpenvlist++;
    }
    /* stringlist have to be freed (specification) */
    free(envlist);

    if (RTEST(opensession)){
        result = pam_close_session(pamh, 0);
        if (result != PAM_SUCCESS) {
            rb_warn("SESSION END: %s", pam_strerror(pamh, result));
        }
        result = pam_end(pamh, result);
        if (result != PAM_SUCCESS) {
            rb_warn("END: %s", pam_strerror(pamh, result));
        }
    }

    return ruby_ret;
}


void Init_rpam2(){
    rpam2 = rb_define_module("Rpam2");
    rb_define_singleton_method(rpam2, "_auth", method_authpam, 5);
    rb_define_singleton_method(rpam2, "account", method_accountpam, 2);
    rb_define_singleton_method(rpam2, "_getenv", method_getenvpam, 7);
    rb_define_singleton_method(rpam2, "_listenv", method_listenvpam, 6);
}
