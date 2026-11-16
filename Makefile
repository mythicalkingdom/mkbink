# Builds into ./build.  Needs Free Pascal (fpc) 3.x; no other libraries.
#
#   src/lib/   library units (bink*.pas)
#   src/app/   programs: mkbink (the mailer), testbink (small example)
#   docs/      the FTS specification texts
#   build/     compiler output
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

clean:
	rm -rf build

.PHONY: all clean
