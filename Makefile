.PHONY: all clean check install copy test

ARCH := $(shell arch)
OS := $(shell uname)

all: test

copy: install
	sudo install --strip ~/.cargo/bin/sshpass /usr/local/bin/sshpass-$(ARCH)-linux
	sudo ln -sf /usr/local/bin/sshpass{-$(ARCH)-linux,}

test: install
	~/.cargo/bin/sshpass -h

install: check
	rustup target add $(ARCH)-unknown-linux-musl
	@echo
	cargo install --target $(ARCH)-unknown-linux-musl --path .
	@echo

check:
	@[[ $(OS) != Linux ]] && { echo "os($(OS)) is unsupported yet" && exit 1; } || true

clean:
	rm -f ~/.cargo/bin/sshpass
