# isomdl

ISO mDL implementation in Rust

## CLI tool

This crate contains a CLI tool. Run the `--help` command to see what actions you can perform.

```bash
cargo run -- --help
```

For example you can get the namespaces and elements defined in an mDL:
```bash
cat test/stringified-mdl.txt | cargo run -- get-namespaces -
```