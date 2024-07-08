Some useful scripts.

# sync-readme-includes.sh

Useful to include code in blocks from README.md file.
This helps to keep the README.md file updated with the code in the source files without manual copy-pasting.  
For example, if you have this:

```
<!-- INCLUDE-RUST: examples/simulated_device_and_reader_basic.rs -->

    ```rust
    
    ```
```

It will include the content of the `examples/simulated_device_and_reader_basic.rs` file in the code block below
the `INCLUDE-RUST`.  
It will keep the `INCLUDE-RUST` marker in the file, so you can run the script again to update the content.

**Run in the same folder where the README.md file is located.**

# sync-doc-includes.sh

Similar as above just for rustdoc comments. If you have this:

```
//! <!-- INCLUDE-RUST: ../examples/simulated_device_and_reader_basic.rs -->
//! ```

//! ```
```

It will include the content of the `examples/simulated_device_and_reader_basic.rs` file in the code block below
the `INCLUDE-RUST`.  
It will keep the `INCLUDE-RUST` marker in the file, so you can run the script again to update the content.

**Run in the root folder, it will run on all `.rs` files recursively.**