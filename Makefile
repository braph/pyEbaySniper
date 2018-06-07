PREFIX = /usr
PROGNAME = pyEbaySniper

build:

install:
	install -m 0755 $(PROGNAME).py $(PREFIX)/bin/$(PROGNAME)
