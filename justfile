default:
    @just --list

fmt:
    zig fmt src/ build.zig

fmt-check:
    zig fmt --check src/ build.zig

build:
    zig build

test:
    zig build test

# Cross-compile matrix (also what CI runs). Add targets here to extend both.
cross:
    zig build -Dtarget=x86_64-linux-gnu

# Integration tests against a real sshd (needs the Docker sftp harness).
integration:
    bash tests/sftp-integration.sh

run *args:
    zig build run -- {{args}}

# Fleet convention: what CI invokes. Run this locally to reproduce CI exactly.
# (fmt-check + build + unit tests + cross-compile matrix; the Docker integration
# suite is `just integration`, kept separate so `ci` stays fast + network-free.)
ci: fmt-check build test cross
    @echo "zioscp ci green"
