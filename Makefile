.PHONY: all clean check_os check_ver install release copy test

ARCH := $(shell arch)
OS := $(shell uname | tr A-Z a-z)

all: test

release: check_ver copy
	tar cJf sshpass-$(VER)-$(ARCH)-$(OS).tar.xz -C /usr/local/bin/ -h sshpass

copy: install
	sudo install --strip ~/.cargo/bin/sshpass /usr/local/bin/sshpass-$(ARCH)-linux
	cd /usr/local/bin && sudo ln -fs sshpass-$(ARCH)-linux sshpass

test: install
	~/.cargo/bin/sshpass -h

install: check_os
	rustup target add $(ARCH)-unknown-linux-musl
	@echo
	cargo install --target $(ARCH)-unknown-linux-musl --path .
	@echo

check_os:
	@[[ $(OS) == linux ]] || { echo "os($(OS)) is unsupported yet" && exit 1; }

check_ver:
	@[[ "$(VER)" ]] || { echo "\$$(VER) needs to be set" && exit 1; }

clean:
	rm -f ~/.cargo/bin/sshpass
