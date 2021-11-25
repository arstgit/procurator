AC_INIT([procurator], [1.1.1], [derekchuank@outlook.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_PROG_CC
AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_new], [AC_DEFINE([HAVE_CRYPTO],[1],[have crypto library])], [AC_MSG_ERROR([library crypto was not found])])
AC_CHECK_LIB([dl], [dlclose])
AC_CHECK_LIB([pthread], [pthread_create])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
])
AC_OUTPUT
