AC_PREREQ(2.60)
AC_INIT([dbuspolicy],
        [1],
        [dev@lists.tizen.org],
        [dbuspolicy],
        [http://review.tizen.org])
AC_CONFIG_SRCDIR([src/libdbuspolicy1.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([
	check-news
	foreign
	1.11
	-Wall
	-Wno-portability
	silent-rules
	tar-pax
	no-dist-gzip
	dist-xz
	subdir-objects
])
AC_PROG_CC_STDC
AC_PROG_CXX
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT([
	disable-static
	pic-only
])
AC_PREFIX_DEFAULT([/usr])

AC_PROG_SED
AC_PROG_MKDIR_P

AC_ARG_ENABLE([logging],
        AS_HELP_STRING([--disable-logging], [disable system logging @<:@default=enabled@:>@]),
        [], enable_logging=yes)
AS_IF([test "x$enable_logging" = "xyes"], [
        AC_DEFINE(ENABLE_LOGGING, [1], [System logging.])
])

AC_ARG_ENABLE([debug],
        AS_HELP_STRING([--enable-debug], [enable debug messages @<:@default=disabled@:>@]),
        [], [enable_debug=no])
AS_IF([test "x$enable_debug" = "xyes"], [
        AC_DEFINE(ENABLE_DEBUG, [1], [Debug messages.])
])

AC_CHECK_FUNCS([ \
	__secure_getenv \
	secure_getenv\
])

my_CFLAGS="\
-Wall \
-Wchar-subscripts \
-Wformat-security \
-Wmissing-declarations \
-Wmissing-prototypes \
-Wnested-externs \
-Wpointer-arith \
-Wshadow \
-Wsign-compare \
-Wstrict-prototypes \
-Wtype-limits \
"
AC_SUBST([my_CFLAGS])

my_CXXFLAGS="\
-Wall \
-std=c++11 \
"

AC_SUBST([my_CXXFLAGS])
PKG_CHECK_MODULES([CYNARA], [cynara-client >= 0.4.2 cynara-session >= 0.4.2],
     [AC_DEFINE([ENABLE_CYNARA], [1], [Define to enable Cynara privilege checks in systemd-bus-proxyd deamon])],
     [AC_MSG_ERROR([libcynara-client-async and cynara-session are required to enable Cynara integration])])

AC_SUBST([CYNARA_CFLAGS])
AC_SUBST([CYNARA_LIBS])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([
        Makefile
])

AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE $VERSION
        =====

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS} ${CYNARA_CFLAGS}
        ldflags:                ${LDFLAGS} ${CYMARA_LIBS}

        logging:                ${enable_logging}
        debug:                  ${enable_debug}
])
