#![no_std]

// As we're pulling all crates in only for their side effects of having symbols (be they required
// on the Rust side like riot_wrappers' panic_handler, or to be used by RIOT like the XFA symbols
// emittted by riot-shell-commands), all these crates have to be extern-crate'd to be pulled in
// even though they're note used on the language level.

extern crate riot_wrappers;

#[cfg(feature = "riot-shell-commands")]
extern crate riot_shell_commands;
