# FUSE of "all nixpkgs"

This is written for learning FUSE. THis is not a practical application.

Requirement: working [Nix](https://nixos.org/) installation (store path must be `/nix/store`).

1. Build a nix-index database by <https://github.com/bennofs/nix-index/> or download a pre-built database from <https://github.com/Mic92/nix-index-database>.
2. Let `MOUNT_POINT=$XDG_RUNTIME_DIR/nixindexfs` or something.
3. Run `cargo run --release -- --db <DB_PATH> $MOUNT_POINT`. Takes 1.5s and requires 1.5G memory in my machine.
4. See `ls -l $MOUNT_POINTS | less` and `ls -l $MOUNT_POINT/bin | less`.
5. Try running `$MOUNT_POINT/bin/hello`. You need network connection. Spoiler: requires X11.
6. Fun with `PATH=$MOUNT_POINT/bin`. But `LD_LIBRARY_PATH=$MOUNT_POINT/lib` is not recommended because some random library cause malfunctions (not investigated yet).
7. Run `umount $MOUNT_POINT` to end the program. If this program is terminated (e.g. Ctr+C), `umount` is required to free the mount point.

Some code is derived from [nix-index](https://github.com/bennofs/nix-index) project.
