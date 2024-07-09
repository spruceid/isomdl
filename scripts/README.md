Some useful scripts.

# sync-md-includes.sh

Useful to include code in code blocks from `makrdown` (`.md`) files, like `README.md.`  
This helps to keep the `README.md` file updated with the code in the source files without manual copy-pasting.  
For example, if you have this:

```
<!-- INCLUDE-RUST: path-to-file-relative-to-md-file -->

    ```rust
    ```
```

It will include the content of the file in the code block below
the `INCLUDE-RUST`. Path to include is relative to the files where the `INCLUDE-RUST` is located.  
It will keep the `INCLUDE-RUST` marker in the file, so you can run the script again to update the content.

You need to specify the path to `md` file

```bash
sync-md-includes.sh README.md
```

# sync-rustdoc-includes.sh

Similar as above just for `rustdoc`. If you have this:

```
//! <!-- INCLUDE-RUST: path-to-file-relative-to-rs-file -->
//! ```
//! ```
```

It will include the content of the file in the code block below
the `INCLUDE-RUST`.  
It will keep the `INCLUDE-RUST` marker in the file, so you can run the script again to update the content.

You need to specify the start directory, and it will run on all `.rs` files recursively.

```bash
sync-rustdoc-includes.sh .
```