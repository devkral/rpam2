require 'mkmf'

abort "missing pam library" unless have_library("pam","pam_start")
abort "missing pam library headers" unless have_header("security/pam_appl.h")
abort "missing pam library headers" unless have_header("security/pam_modules.h")

have_func("pam_end")
have_func("pam_open_session")
have_func("pam_close_session")
have_func("pam_authenticate")
have_func("pam_acct_mgmt")
have_func("pam_chauthtok")
have_func("pam_set_item")
have_func("pam_get_item")
$CFLAGS << " -std=c99 "


create_makefile("rpam2/rpam2")
