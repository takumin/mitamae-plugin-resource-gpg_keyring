.PHONY: all
all: test

.PHONY: clean
clean:
	rm -fr .plugins
	git clean -xdf

.PHONY: setup
setup:
ifeq (,$(wildcard .plugins))
	@mkdir -p .plugins
	@ln -s .. .plugins/$(shell basename $(CURDIR))
endif

.PHONY: test
test: setup
	mitamae local --log-level=debug --plugins=.plugins test/recipe/keyring.rb
