# NintendoClients-rs

> :warning: This crate talks to Nintendo's servers. Using it is at your own risk. Make sure that you know what you are doing.

A Rust port of the 3DS account client and the 3DS/Wii U friend clients from
[NintendoClients](https://github.com/kinnay/NintendoClients).

## Usage

The crate requires Rust 1.75 or later and is not published on crates.io yet,
so add it as a git dependency:

```toml
[dependencies]
nintendoclients = { git = "https://github.com/3DS-RPC/NintendoClients-rs" }
```

See `examples/` for complete flows (`real_3ds`, `local_friends`, `local_login`).
Protocol details are documented in the
[NintendoClients wiki](https://github.com/kinnay/NintendoClients/wiki).

## Logging

The crate uses the [`log`](https://crates.io/crates/log) facade. Client calls
log at `INFO`, connection and RMC details at `DEBUG`, and raw packets at
`TRACE`. The examples initialize `env_logger`:

```console
RUST_LOG=nintendoclients=info cargo run --example real_3ds -- pretendo
RUST_LOG=nintendoclients=debug cargo run --example local_friends
```

## Development

The `reference` branch contains a stripped-down fork of
[NintendoClients v4.4.0](https://github.com/kinnay/NintendoClients/tree/41f848ac38c748a575141eae82a2cde133d2fd90).

```console
cargo build
cargo test
```
