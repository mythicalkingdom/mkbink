# Builds into ./build.  Needs Free Pascal (fpc) 3.x; no other libraries.
#
#   src/lib/   library units (bink*.pas)
#   src/app/   programs: mkbink (the mailer), testbink (small example)
#   docs/      the FTS specification texts
#   build/     compiler output
FPC    = fpc
FLAGS  = -FUbuild -FEbuild -Fusrc/lib -vewn
UNITS  = $(wildcard src/lib/*.pas)

all: build/mkbink build/testbink

build:
	mkdir -p build

build/mkbink: build src/app/mkbink.pas $(UNITS)
	$(FPC) $(FLAGS) src/app/mkbink.pas

build/testbink: build src/app/testbink.pas $(UNITS)
	$(FPC) $(FLAGS) src/app/testbink.pas

clean:
	rm -rf build

.PHONY: all clean
