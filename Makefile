.PHONY: install uninstall

install:
	./setup.py install --record files.txt
uninstall:
	cat files.txt | xargs rm -rf