# This file is part of systemd.
#
# Used by systemd --user instances.

account  include common-account

m4_ifdef(`HAVE_SELINUX',
session  required pam_selinux.so close
session  required pam_selinux.so nottys open
)m4_dnl
session  include common-session
