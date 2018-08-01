#-------------------------------------------------------------------------
#
# Makefile for src/bin/pgxc_clean
#
# Portions Copyright (c) 2011-2012 Postgres-XC Development Group
#
# $PostgreSQL$
#
#-------------------------------------------------------------------------

PGFILEDESC = "pgxc_clean - Resolve prepared transactions in PGXL cluster"
PGAPPICON = win32

subdir = src/bin/pgxc_clean
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS= pgxc_clean.o txninfo.o

#Include GTM objects
gtm_builddir = $(top_builddir)/src/gtm
EX_OBJS = $(gtm_builddir)/common/assert.o \
	  $(gtm_builddir)/client/libgtmclient.a

PG_CPPFLAGS  = -DFRONTEND -DDLSUFFIX=\"$(DLSUFFIX)\" -I$(srcdir) -I$(libpq_srcdir)
PG_LIBS = $(libpq_pgport) $(PTHREAD_LIBS)

override CPPFLAGS := $(PG_CPPFLAGS) $(CPPFLAGS)
override LDFLAGS := $(PG_LIBS) $(LDFLAGS)

SUBMAKE_LIBPQ := submake-libpq
SUBMAKE_GTMLIB := submake-gtmlib

all: pgxc_clean

pgxc_clean: $(OBJS) $(EX_OBJS) | $(SUBMAKE_LIBPQ) $(SUBMAKE_GTMLIB)
	$(CC) $(CFLAGS) $(OBJS) $(EX_OBJS) $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@$(X)

install: all installdirs
	$(INSTALL_PROGRAM) pgxc_clean$(X) '$(DESTDIR)$(bindir)/pgxc_clean$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

uninstall:
	rm -f '$(DESTDIR)$(bindir)/pgxc_clean$(X)'

clean distclean maintainer-clean:
	rm -f pgxc_clean$(X) $(OBJS)
	rm -rf tmp_check

check:
	$(prove_check)

installcheck:
	$(prove_installcheck)
