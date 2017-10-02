#include "ruby.h"
#include <string.h>
#include <security/pam_appl.h>

static const char *const
rpam_default_servicename = "rpam";

struct auth_wrapper{
  char* pw;
};

static VALUE
method_authpam(VALUE self, VALUE servicename, VALUE username, VALUE password);

static VALUE
method_accountpam(VALUE self, VALUE servicename, VALUE username);

static VALUE
method_getenvpam(VALUE self, VALUE servicename, VALUE username, VALUE password, VALUE envname, VALUE opensession);

static VALUE
method_listenvpam(VALUE self, VALUE servicename, VALUE username, VALUE password, VALUE opensession);


VALUE rpam2;
void Init_rpam2(){
    rpam2 = rb_define_module("Rpam2");
    rb_define_singleton_method(rpam2, "auth", method_authpam, 3);
    rb_define_singleton_method(rpam2, "account", method_accountpam, 2);
    rb_define_singleton_method(rpam2, "getenv", method_getenvpam, 5);
    rb_define_singleton_method(rpam2, "listenv", method_listenvpam, 4);
}

int rpam_auth_conversation(int num_msg, const struct pam_message **msgm,
                           struct pam_response **resp, void *appdata_ptr){
    struct pam_response *responses = calloc(num_msg, sizeof(struct pam_response));
    // no space for responses
    if (!responses)
        return PAM_BUF_ERR;
    struct auth_wrapper *authw = (struct auth_wrapper *)appdata_ptr;
    for (int msgc=0; msgc<num_msg; msgc++){
        switch (msgm[msgc]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                // Assume ECHO_OFF is password/secret input
                responses[msgc].resp = strdup(authw->pw);
                break;
            case PAM_PROMPT_ECHO_ON:
            case PAM_TEXT_INFO:
                // ignore, they should not occur but some verbose applications exist always
                responses[msgc].resp = strdup("");
                break;
            case PAM_ERROR_MSG:
                // print error message
                rb_warn("%s", msgm[msgc]->msg);
                responses[msgc].resp = strdup("");
                break;
            default:
                free(responses);
                return PAM_CONV_ERR;
        }
        // response could not be allocated (no space)
        if(responses[msgc].resp==0){
            free(responses);
            return PAM_BUF_ERR;
        }
    }
    *resp = responses;
    return PAM_SUCCESS;
}

static VALUE method_authpam(VALUE self, VALUE servicename, VALUE username, VALUE password) {
    pam_handle_t* pamh = NULL;
    unsigned int result=0;
    Check_Type(username, T_STRING);
    Check_Type(password, T_STRING);

    char *service = (char*)rpam_default_servicename;
    if(!NIL_P(servicename)){
        service = StringValueCStr(servicename);
    }

    struct pam_conv auth_c;
    auth_c.conv = rpam_auth_conversation;

    struct auth_wrapper authw;
    authw.pw = StringValueCStr(password);
    auth_c.appdata_ptr = &authw;

    pam_start(service, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("INIT: %s", pam_strerror(pamh, result));
        return Qfalse;
    }

    result = pam_acct_mgmt(pamh, 0);
    if (result != PAM_SUCCESS) {
        pam_end(pamh, result);
        return Qfalse;
    }

    result = pam_authenticate(pamh, 0);
    if (result != PAM_SUCCESS) {
        pam_end(pamh, result);
        return Qfalse;
    }

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
    Check_Type(username, T_STRING);

    char *service = (char*)rpam_default_servicename;
    if(!NIL_P(servicename)){
        service = StringValueCStr(servicename);
    }

    struct pam_conv auth_c = {0,0};
    pam_start(service, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("INIT: %s", pam_strerror(pamh, result));
        return Qfalse;
    }

    result = pam_acct_mgmt(pamh, 0);
    if (result != PAM_SUCCESS) {
        pam_end(pamh, result);
        return Qfalse;
    }

    if (pam_end(pamh, result) == PAM_SUCCESS)
        return Qtrue;
    else {
        rb_warn("END: %s", pam_strerror(pamh, result));
        return Qfalse;
    }
}


static VALUE method_getenvpam(VALUE self, VALUE servicename, VALUE username, VALUE password, VALUE envname, VALUE opensession) {
    pam_handle_t* pamh = NULL;
    unsigned int result=0;
    VALUE ret2;
    Check_Type(username, T_STRING);
    Check_Type(password, T_STRING);
    Check_Type(envname, T_STRING);

    char *service = (char*)rpam_default_servicename;
    if(!NIL_P(servicename)){
        service = StringValueCStr(servicename);
    }

    struct pam_conv auth_c;
    auth_c.conv = rpam_auth_conversation;

    struct auth_wrapper authw;
    authw.pw = StringValueCStr(password);
    auth_c.appdata_ptr = &authw;

    pam_start(service, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("INIT: %s", pam_strerror(pamh, result));
        return Qnil;
    }

    result = pam_authenticate(pamh, 0);
    if (result != PAM_SUCCESS) {
        pam_end(pamh, result);
        return Qnil;
    }

    if (RTEST(opensession)){
        result = pam_open_session(pamh, 0);
        if (result != PAM_SUCCESS) {
            rb_warn("SESSION OPEN: %s", pam_strerror(pamh, result));
            pam_end(pamh, result);
            return Qnil;
        }
    }
    char *ret = pam_getenv(pamh, StringValueCStr(envname));
    if(ret){
        ret2 = rb_str_new_cstr(ret);
    } else {
        ret2 = Qnil;
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
    return ret2;
}

static VALUE method_listenvpam(VALUE self, VALUE servicename, VALUE username, VALUE password, VALUE opensession) {
    pam_handle_t* pamh = NULL;
    unsigned int result=0;
    Check_Type(username, T_STRING);
    Check_Type(password, T_STRING);

    char *service = (char*)rpam_default_servicename;
    if(!NIL_P(servicename)){
        service = StringValueCStr(servicename);
    }

    struct pam_conv auth_c;
    auth_c.conv = rpam_auth_conversation;

    struct auth_wrapper authw;
    authw.pw = StringValueCStr(password);
    auth_c.appdata_ptr = &authw;

    pam_start(service, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("INIT: %s", pam_strerror(pamh, result));
        return Qnil;
    }

    result = pam_authenticate(pamh, 0);
    if (result != PAM_SUCCESS) {
        pam_end(pamh, result);
        return Qnil;
    }

    if (RTEST(opensession)){
        result = pam_open_session(pamh, 0);
        if (result != PAM_SUCCESS) {
            rb_warn("SESSION OPEN: %s", pam_strerror(pamh, result));
            pam_end(pamh, result);
            return Qnil;
        }
    }

    char **envlist = pam_getenvlist(pamh);
    VALUE ret = rb_hash_new();
    char **tmpenvlist=envlist;
    while(*tmpenvlist!=NULL){
        char *last = strchr(*tmpenvlist, '=');
        // should not be needed but better be safe in a security relevant application
        if (last!=NULL){
            rb_hash_aset(ret, rb_str_new(*tmpenvlist, last-*tmpenvlist), rb_str_new_cstr(last+1));
        }
        // strings have to be freed (specification)
        // overwrite them with zero to prevent leakage
        memset(*tmpenvlist, 0, strlen(*tmpenvlist));
        free(*tmpenvlist);
        tmpenvlist++;
    }
    // stringlist have to be freed (specification)
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

    return ret;
}

