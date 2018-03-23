require 'mkmf'

pam_installed = have_library("pam","pam_start") and have_header("security/pam_appl.h")
#pam_installed = false


abort "missing pam library or header" unless pam_installed || ENV['ALLOW_NOPAM']=='true'


$CFLAGS << " -std=c99 "

if pam_installed
  puts "Rpam2 build correctly (without stubs)" if ENV['ALLOW_NOPAM']=='true'
  have_func("pam_end")
  have_func("pam_open_session")
  have_func("pam_close_session")
  have_func("pam_authenticate")
  have_func("pam_acct_mgmt")
  have_func("pam_set_item")
  have_func("pam_get_item")
else
  warn "Rpam2 build didn't find pam headers/library, use pam stubs.\nONLY FOR TESTS OR IF PAM IS NOT USED. THIS MODE IS NOT SAFE IF PAM IS USED."
  $CFLAGS << "-DWITHOUT_PAM_HEADER=1 "
end


create_makefile("rpam2/rpam2")
