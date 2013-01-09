VERSION = 1
NAME = hostwakeup
ARCHIVE = $(NAME)-$(VERSION)
PACKAGE = yavdr-$(ARCHIVE)
TMPDIR = /tmp

dist:
	@-rm -rf $(TMPDIR)/$(ARCHIVE)
	@mkdir $(TMPDIR)/$(ARCHIVE)
	@cp -a * $(TMPDIR)/$(ARCHIVE)
	@tar czf $(PACKAGE).tgz -C $(TMPDIR) $(ARCHIVE)
	@-rm -rf $(TMPDIR)/$(ARCHIVE)
	@echo Distribution package created as $(PACKAGE).tgz

clean:

