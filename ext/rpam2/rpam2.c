#include "ruby.h"
#include <security/pam_appl.h>

static const char
*rpam_default_servicename = "rpam";

VALUE rpam2;
void Init_Rpam2();

static VALUE method_authpam(VALUE self, VALUE servicename, VALUE username, VALUE password) {
    pam_handle_t* pamh = NULL;
    unsigned int result=0;
    Check_Type(username, T_STRING);
    Check_Type(password, T_STRING);

    char *service = rpam_default_servicename;
    if(!NIL_P(servicename)){
        service = StringValueCStr(servicename);
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
    rpam2 = rb_define_module("Rpam2");
    rb_define_singleton_method(rpam2, "authpam", method_authpam, 3);
}
