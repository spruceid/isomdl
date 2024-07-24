Some useful scripts.

# update-md-includes.sh

Useful to include code in code blocks from `markdown` (`.md`) files, like `README.md.`  
This helps to keep the `README.md` file updated with the code in the source files without manually copy-pasting.  
For example, if you have this:

```markdown
<!-- INCLUDE-RUST: path-relative-to-md-file -->

    ```rust
    ```
```

It will include the content of the file in the code block below
the `INCLUDE-RUST`. Path to include is relative to the files where the `INCLUDE-RUST` is located.  
It will keep the `INCLUDE-RUST` marker in the file, so you can run the script again to update the content.

You need to specify the path to the `md` file as input.

```bash
update-md-includes.sh README.md
```
