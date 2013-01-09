VERSION = 2
NAME = hostwakeup
ARCHIVE = $(NAME)-$(VERSION)
PACKAGE = yavdr-$(ARCHIVE)
TMPDIR = /tmp

hostwakeup-example: hostwakeup-example.c
	gcc -o hostwakeup-example hostwakeup-example.c `pkg-config --cflags dbus-1` `pkg-config --libs dbus-1`

dist:
	@-rm -rf $(TMPDIR)/$(ARCHIVE)
	@mkdir $(TMPDIR)/$(ARCHIVE)
	@cp -a * $(TMPDIR)/$(ARCHIVE)
	@tar czf $(PACKAGE).tgz -C $(TMPDIR) $(ARCHIVE)
	@-rm -rf $(TMPDIR)/$(ARCHIVE)
	@echo Distribution package created as $(PACKAGE).tgz

clean:
	@rm -f hostwakeup-example
