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

run *args:
    zig build run -- {{args}}

# Fleet convention: what CI invokes.
ci: fmt-check build test
    @echo "zioscp ci green"
