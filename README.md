# rust-version sshpass

sshpass offers you the ability to automatically offer a password via SSH when
you are prompted for it.

## Install

### compile from source

```bash
git clone https://github.com/ling-zhou/rust-sshpass
cd rust-sshpass
make
~/.cargo/bin/sshpass -h
```

### download prebuilt binaries


## Notes

This repository is fully compatible with https://github.com/kevinburke/sshpass

**Comparison with https://github.com/kevinburke/sshpass**

✅ 1. option parsing is not affected by subcommand options

❗ 2. the original password from '-p' can not be hidden because of the limit of rust
