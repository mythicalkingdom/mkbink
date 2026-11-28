# SPDX-License-Identifier: GPL-3.0-or-later
# Builds into ./build.  Needs Free Pascal (fpc) 3.x; no other libraries.
#
#   src/lib/   library units (bink*.pas)
#   src/app/   programs: mkbink (the mailer), testbink (small example)
#   docs/      the FTS specification texts
#   build/     compiler output
#
#   make                  build build/mkbink (and the small example build/testbink)
#   make install          install mkbink and its notes (as root, or into a staging
#                         directory with DESTDIR)
#   make uninstall        remove them again
#
# Variables:  PREFIX=/usr/local  BINDIR=$(PREFIX)/bin
#             DOCDIR=$(PREFIX)/share/doc/mkbink  DESTDIR=  (staging directory)
#             MKMSG=../mk-fpc/src  the MKMsg units for attach style (see below)
#   e.g.  make && sudo make install
#         make install PREFIX=$HOME/.local
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DOCDIR ?= $(PREFIX)/share/doc/mkbink
DESTDIR ?=
FPC    = fpc
FLAGS  = -FUbuild -FEbuild -Fusrc/lib -vewn
UNITS  = $(wildcard src/lib/*.pas)

# Attach (FrontDoor) style outbound needs the MKMsg units of the MK BBS
# (MKMsgFid and what it uses).  They are found in ../mk-fpc/src, or set
# MKMSG=dir; without them mkbink is built without that style.
MKMSG ?= ../mk-fpc/src
ifneq ($(wildcard $(MKMSG)/MKMsgFid.pas),)
FLAGS += -dMKMSG -Fu$(MKMSG)
MKMSGSTAMP = build/mkmsg.stamp
else
UNITS := $(filter-out src/lib/binkattach.pas,$(UNITS))
endif

all: build/mkbink build/testbink

build:
	mkdir -p build

# the MKMsg units are compiled quietly (they are not ours)
build/mkmsg.stamp: build $(wildcard $(MKMSG)/MK*.pas)
	$(FPC) -FUbuild -FEbuild -Fu$(MKMSG) -v0 $(MKMSG)/MKMsgFid.pas
	touch $@

build/mkbink: build $(MKMSGSTAMP) src/app/mkbink.pas $(UNITS)
	$(FPC) $(FLAGS) src/app/mkbink.pas

build/testbink: build src/app/testbink.pas $(UNITS)
	$(FPC) $(FLAGS) src/app/testbink.pas

# The mailer only: the MK BBS makefile (make install there) calls
# "make build/mkbink" here and installs the result itself.
install: build/mkbink
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(DOCDIR)
	install -m 755 build/mkbink $(DESTDIR)$(BINDIR)/mkbink
	install -m 644 NOTES.md $(DESTDIR)$(DOCDIR)/NOTES.md
	install -m 644 docs/*.txt $(DESTDIR)$(DOCDIR)/
	@echo "installed mkbink in $(DESTDIR)$(BINDIR), notes and the FTS texts in $(DESTDIR)$(DOCDIR)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/mkbink
	rm -rf $(DESTDIR)$(DOCDIR)
	@echo "removed mkbink and $(DESTDIR)$(DOCDIR)"

clean:
	rm -rf build

.PHONY: all install uninstall clean
