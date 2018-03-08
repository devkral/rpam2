require 'mkmf'

abort "missing pam library" unless have_library("pam","pam_start")

use_pam_header = have_header("security/pam_appl.h")
#use_pam_header = false



have_func("pam_end")
have_func("pam_open_session")
have_func("pam_close_session")
have_func("pam_authenticate")
have_func("pam_acct_mgmt")
have_func("pam_set_item")
have_func("pam_get_item")
$CFLAGS << " -std=c99 "

if use_pam_header
  puts "Rpam2 build with pam header."
else
  puts "Rpam2 build without pam header, use pam polyfills."
  $CFLAGS << "-DWITHOUT_PAM_HEADER=1 "
end


create_makefile("rpam2/rpam2")
