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
    src/internal/internal.cpp

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

TESTS = src/test-libdbuspolicy1

check_PROGRAMS = src/test-libdbuspolicy1
src_test_libdbuspolicy1_SOURCES = src/test-libdbuspolicy1.c
src_test_libdbuspolicy1_LDADD = src/libdbuspolicy1.la $(CYNARA_LIBS)
