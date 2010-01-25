dnl Process this file with autoconf to produce a configure script.

AC_INIT(speedkey, 0.0.2, http://github.com/potyl/speedkey)
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_SRCDIR([src])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_MAINTAINER_MODE
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Libraries
AC_SEARCH_LIBS([pthread_create], [pthread])

# Make sure we keep ACLOCAL_FLAGS around for maintainer builds to work
AC_SUBST(ACLOCAL_AMFLAGS, "$ACLOCAL_FLAGS -I m4")

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT
