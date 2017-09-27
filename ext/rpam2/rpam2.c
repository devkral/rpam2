#include "ruby.h"
#include <security/pam_appl.h>

static const char *const
rpam_default_servicename = "rpam";


static VALUE
method_authpam(VALUE self, VALUE servicename, VALUE username, VALUE password);

static VALUE
method_accountpam(VALUE self, VALUE servicename, VALUE username);

VALUE rpam2;
void Init_rpam2(){
    rpam2 = rb_define_module("Rpam2");
    rb_define_singleton_method(rpam2, "authpam", method_authpam, 3);
    rb_define_singleton_method(rpam2, "accountpam", method_accountpam, 2);
}

int rpam_auth_conversation(int num_msg, const struct pam_message **msgm,
                           struct pam_response **responses, void *appdata_ptr){
    responses = calloc(num_msg, sizeof(struct pam_response));
    // no space for responses
    if (!responses)
        return PAM_BUF_ERR;
    char *pw = (char *)appdata_ptr;
    for (int msgc=0; msgc<num_msg; msgc++){
        switch (msgm[msgc]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                // Assume ECHO_OFF is password/secret input
                responses[msgc]->resp = strdup(pw);
            case PAM_PROMPT_ECHO_ON:
            case PAM_TEXT_INFO:
                // ignore, they should not occur but some verbose applications exist always
                responses[msgc]->resp = strdup("");
                break;
            case PAM_ERROR_MSG:
                // print error message
                rb_warn("%s", msgm[msgc]->msg);
                responses[msgc]->resp = strdup("");
                break;
            default:
                free(responses);
                return PAM_CONV_ERR;
        }
        // response could not be allocated (no space)
        if(responses[msgc]->resp==0){
            free(responses);
            return PAM_BUF_ERR;
        }
    }
    return PAM_SUCCESS;
}

static VALUE method_authpam(VALUE self, VALUE servicename, VALUE username, VALUE password) {
    pam_handle_t* pamh = NULL;
    unsigned int result=0;
    Check_Type(username, T_STRING);
    Check_Type(password, T_STRING);

    char *service = rpam_default_servicename;
    if(!NIL_P(servicename)){
        service = StringValueCStr(servicename);
    }

    struct pam_conv auth_c;
    auth_c.conv = rpam_auth_conversation;
    auth_c.appdata_ptr = StringValueCStr(password);

    pam_start(service, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("pam initialisation failed");
        return Qfalse;
    }

    result = pam_authenticate(pamh, 0);
    if (result != PAM_SUCCESS) {
        pam_end(pamh, result);
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
        rb_warn("pam end failed");
        return Qfalse;
    }
}

static VALUE method_accountpam(VALUE self, VALUE servicename, VALUE username) {
    pam_handle_t* pamh = NULL;
    unsigned int result=0;
    Check_Type(username, T_STRING);

    char *service = rpam_default_servicename;
    if(!NIL_P(servicename)){
        service = StringValueCStr(servicename);
    }

    struct pam_conv auth_c = {0,0};
    pam_start(service, StringValueCStr(username), &auth_c, &pamh);
    if (result != PAM_SUCCESS) {
        rb_warn("pam initialisation failed");
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
        rb_warn("pam end failed");
        return Qfalse;
    }
}
