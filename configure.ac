dnl
dnl This file is part of Sylverant PSO Server.
dnl
dnl Copyright (C) 2009, 2011, 2018 Lawrence Sebald
dnl
dnl This program is free software: you can redistribute it and/or modify
dnl it under the terms of the GNU Affero General Public License version 3
dnl as published by the Free Software Foundation.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU Affero General Public License for more details.
dnl
dnl You should have received a copy of the GNU Affero General Public License
dnl along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.61])
AC_INIT([shipgate], [0.1.0])
AC_CONFIG_MACRO_DIR([m4])

version_major=0
version_minor=1
version_micro=0

AC_SUBST([version_major])
AC_SUBST([version_minor])
AC_SUBST([version_micro])

AC_DEFINE_UNQUOTED([VERSION_MAJOR], [$version_major], [Major Package Version])
AC_DEFINE_UNQUOTED([VERSION_MINOR], [$version_minor], [Minor Package Version])
AC_DEFINE_UNQUOTED([VERSION_MICRO], [$version_micro], [Micro Package Version])

AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([subdir-objects])
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_LANG(C)

AC_CONFIG_SRCDIR([src/packets.c])

# Checks for programs.
AC_PROG_CC

AM_ICONV
AM_ICONV_LINK

# Checks for libraries.
PKG_CHECK_MODULES([libxml2], [libxml-2.0 >= 2.7])
CFLAGS="$CFLAGS $libxml2_CFLAGS"
LIBS="$LIBS $libxml2_LIBS"

PKG_CHECK_MODULES([gnutls], [gnutls >= 2.0])
CFLAGS="$CFLAGS $gnutls_CFLAGS"
LIBS="$LIBS $gnutls_LIBS"

MYSQL_CLIENT()
AC_CHECK_LIB([sylverant], [sylverant_read_config], , AC_MSG_ERROR([libsylverant is required!]))
AC_CHECK_LIB([z], [compress2], , AC_MSG_ERROR([zlib is required!]))
AC_SEARCH_LIBS([pidfile_open], [util bsd], [NEED_PIDFILE=0], [NEED_PIDFILE=1])

MYSQL_LIBS="`mysql_config --libs`"
AC_SUBST(MYSQL_LIBS)
AM_CONDITIONAL([NEED_PIDFILE], [test "$NEED_PIDFILE" -eq 1])

AC_ARG_ENABLE([scripting], [AS_HELP_STRING([--enable-scripting],
              [enable scripting support in the binary (requires Lua 5.3.x)])],
              [enable_scripting=$enableval],
              [enable_scripting=no])

AS_IF([test "x$enable_scripting" != xno], [
    PKG_CHECK_MODULES([lua], [lua-5.3], , [
        PKG_CHECK_MODULES([lua], [lua5.3], , [
            PKG_CHECK_MODULES([lua], [lua >= 5.3], , [
                AC_MSG_ERROR([Scripting support requires Lua 5.3.x!])
            ])
        ])
    ])

    CFLAGS="$CFLAGS $lua_CFLAGS -DENABLE_LUA"
    LIBS="$LIBS $lua_LIBS"
])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h pwd.h grp.h])
AC_CHECK_HEADERS([libutil.h bsd/libutil.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_C_BIGENDIAN
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long int])
AC_CHECK_SIZEOF([void*])

# Checks for library functions.
AC_CHECK_FUNCS([malloc realloc inet_ntoa memmove memset select socket getgrouplist])

ADD_CFLAGS([-Wall])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
