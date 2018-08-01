#-------------------------------------------------------------------------
#
# Makefile for src/bin/pgxc_ctl
#
# Portions Copyright (c) 2013 Postgres-XC Development Group
#
# $PostgreSQL$
#
#-------------------------------------------------------------------------

PGFILEDESC = "pgxc_ctl - Provide XC configuration and opeation"
PGAPPICON = win32

subdir = src/bin/pgxc_ctl
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS= pgxc_ctl_bash.o bash_handler.o config.o pgxc_ctl.o variables.o pgxc_ctl_log.o do_command.o \
	 utils.o do_shell.o gtm_cmd.o coord_cmd.o datanode_cmd.o gtm_util.o mcxt.o monitor.o

#Include GTM objects
gtm_builddir = $(top_builddir)/src/gtm
EX_OBJS = $(gtm_builddir)/common/assert.o \
	  $(gtm_builddir)/client/libgtmclient.a \
	  $(gtm_builddir)/common/gtm_serialize.o

PG_CPPFLAGS  = -DFRONTEND -DDLSUFFIX=\"$(DLSUFFIX)\" -I$(srcdir) -I$(libpq_srcdir) -I.
PG_LIBS = $(libpq_pgport) $(PTHREAD_LIBS)

override CPPFLAGS := $(PG_CPPFLAGS) $(CPPFLAGS)
override LDFLAGS := $(PG_LIBS) $(LDFLAGS)

SUBMAKE_LIBPQ := submake-libpq
SUBMAKE_GTMLIB := submake-gtmlib

.PHONY: MAKE_SIGNATURE
MAKE_SIGNATURE: pgxc_ctl_conf_part_full pgxc_ctl_conf_part_minimal pgxc_ctl_conf_part_empty pgxc_ctl_bash_2
	cd $(top_srcdir)/$(subdir) && ./make_signature
ifeq ($(vpath_build),yes)
	mv $(top_srcdir)/$(subdir)/signature.h .
	mv $(top_srcdir)/$(subdir)/pgxc_ctl_bash.c .
endif

pgxc_ctl_bash.c: MAKE_SIGNATURE

all: pgxc_ctl

pgxc_ctl: $(OBJS) $(EX_OBJS) | $(SUBMAKE_LIBPQ) $(SUBMAKE_GTMLIB)
	$(CC) $(CFLAGS) $(OBJS) $(EX_OBJS) $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@$(X)

install: all installdirs
	$(INSTALL_PROGRAM) pgxc_ctl$(X) '$(DESTDIR)$(bindir)/pgxc_ctl$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

uninstall:
	rm -f '$(DESTDIR)$(bindir)/pgxc_ctl$(X)'

clean distclean maintainer-clean:
	rm -f pgxc_ctl$(X) $(OBJS)
	rm -rf tmp_check
	rm -f pgxc_ctl_bash.c signature.h

check:
	$(prove_check)

installcheck:
	$(prove_installcheck)
