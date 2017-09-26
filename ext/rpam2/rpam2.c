#include "ruby.h"
#include <security/pam_appl.h>

static const char
*rpam_default_servicename = "rpam";

VALUE rpam2;
void Init_rpam2();

static VALUE method_authpam(VALUE servicename, VALUE username, VALUE password) {
    pam_handle_t* pamh = NULL;
    unsigned int result=0;
    char *service = rpam_default_servicename;
    switch (TYPE(servicename))
    {
        case T_STRING:
            /* handle string */
            service = StringValueCStr(servicename);
            break;
        case T_NIL:
            /* handle nil */
            break;
        default:
            rb_raise(rb_eTypeError, "Only String and nil are valid servicename types");
    }
    pam_start(service, StringValueCStr(username), NULL, &pamh);
    if (result != PAM_SUCCESS) {
        return Qfalse;
    }
    // don't implement whole dialog
    result = pam_set_item(pamh, PAM_AUTHTOK, StringValueCStr(password));
    if (result != PAM_SUCCESS) {
        pam_end(pamh, result);
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
    else
        return Qfalse;
}

void Init_rpam2() {
    rpam2 = rb_define_module("rpam2");
    rb_define_method(rpam2, "authpam", method_authpam, 3);
}
