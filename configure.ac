dnl Process this file with autoconf to produce a configure script.

AC_INIT(speedkey, 0.0.9, http://github.com/potyl/speedkey)
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_MAINTAINER_MODE
AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Libraries
AC_SEARCH_LIBS([pthread_create], [pthread])


# -----------------------------------------------------------
# Enable openssl
# -----------------------------------------------------------

AC_ARG_ENABLE(
	openssl,
	AS_HELP_STRING([--disable-openssl],[Do not compile with OpenSSL support]),
	enable_openssl=$enableval, enable_openssl=yes
)

if test x$enable_openssl = xyes; then
	PKG_CHECK_MODULES(OPENSSL, [ openssl >= 0.9.8 ])
	AC_SUBST(OPENSSL_CFLAGS)
	AC_SUBST(OPENSSL_LIBS)
fi

AM_CONDITIONAL(HAS_OPENSSL, test "x$enable_openssl" = "xyes")



# Make sure we keep ACLOCAL_FLAGS around for maintainer builds to work
AC_SUBST(ACLOCAL_AMFLAGS, "$ACLOCAL_FLAGS -I m4")

AC_CONFIG_FILES([Makefile sha1/Makefile src/Makefile])

CFLAGS="$CFLAGS -W -Wall -Wextra -Werror"

AC_OUTPUT
