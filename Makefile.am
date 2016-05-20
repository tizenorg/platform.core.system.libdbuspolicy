EXTRA_DIST =
CLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_MAKEFLAGS = --no-print-directory

AM_CXXFLAGS = ${my_CXXFLAGS}

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
        $(CYNARA_CFLAGS) \
	-I${top_srcdir}/src

AM_CFLAGS = ${my_CFLAGS} \
	-fvisibility=hidden \
	-ffunction-sections \
        $(CYNARA_CFLAGS) \
	-fdata-sections

AM_LDFLAGS = \
	-Wl,--gc-sections \
	-Wl,--as-needed \
	$(CYNARA_CFLAGS) \
	$(CYNARA_LIBS)\
	-pthread

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && $(SED) \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@exec_prefix\@,$(exec_prefix),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@includedir\@,$(includedir),g' \
	< $< > $@ || rm $@

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

LIBDBUSPOLICY1_CURRENT=1
LIBDBUSPOLICY1_REVISION=0
LIBDBUSPOLICY1_AGE=0

pkginclude_HEADERS = src/dbuspolicy1/libdbuspolicy1.h
lib_LTLIBRARIES = src/libdbuspolicy1.la

src_libdbuspolicy1_la_SOURCES =\
	src/libdbuspolicy1-private.h \
	src/libdbuspolicy1.c \
	src/internal/internal.cpp \
	src/internal/naive_policy_checker.cpp \
	src/internal/naive_policy_db.cpp \
	src/internal/policy.cpp \
	src/internal/xml_parser.cpp \
	src/internal/tslog.cpp \
	src/internal/cynara.cpp

EXTRA_DIST += src/libdbuspolicy1.sym

src_libdbuspolicy1_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBDBUSPOLICY1_CURRENT):$(LIBDBUSPOLICY1_REVISION):$(LIBDBUSPOLICY1_AGE) \
        $(CYNARA_LIBS) \
	-Wl,--version-script=$(top_srcdir)/src/libdbuspolicy1.sym
src_libdbuspolicy1_la_DEPENDENCIES = ${top_srcdir}/src/libdbuspolicy1.sym

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = src/libdbuspolicy1.pc
EXTRA_DIST += src/libdbuspolicy1.pc.in
CLEANFILES += src/libdbuspolicy1.pc

TESTS = src/test-libdbuspolicy1-ownership \
	src/test-libdbuspolicy1-signal \
	src/test-libdbuspolicy1-method

check_PROGRAMS = src/test-libdbuspolicy1-ownership \
    src/test-libdbuspolicy1-signal \
    src/test-libdbuspolicy1-method

src_test_libdbuspolicy1_ownership_SOURCES = src/test-libdbuspolicy1-ownership.cpp
src_test_libdbuspolicy1_signal_SOURCES = src/test-libdbuspolicy1-signal.cpp
src_test_libdbuspolicy1_method_SOURCES = src/test-libdbuspolicy1-method.cpp

noinst_LTLIBRARIES = src/libinternal.a
src_libinternal_a_SOURCES =\
	src/libdbuspolicy1-private.h \
	src/internal/internal.cpp \
	src/libdbuspolicy1.c \
	src/internal/naive_policy_checker.cpp \
	src/internal/naive_policy_db.cpp \
	src/internal/policy.cpp \
	src/internal/xml_parser.cpp \
	src/internal/tslog.cpp \
	src/internal/cynara_mockup.cpp

libinternal_a_LIBADD = $(CYNARA_LIBS)

src_test_libdbuspolicy1_ownership_LDADD = $(CYNARA_LIBS) \
	src/libinternal.a

src_test_libdbuspolicy1_signal_LDADD = $(CYNARA_LIBS) \
	src/libinternal.a

src_test_libdbuspolicy1_method_LDADD = $(CYNARA_LIBS) \
	src/libinternal.a
