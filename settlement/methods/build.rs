use std::collections::HashMap;

use risc0_build::{embed_methods_with_options, GuestOptionsBuilder};

fn main() {
    // The default build keeps `guest-epoch` lean (E1/E3 only). Setting
    // `AEGIS_EPOCH_AUXPOW=1` builds it WITH the `aux-pow` feature (E2 in-guest
    // share verify + E4 canonical-Ergo anchor linkage) — the M-E1 cross-compile
    // + cycle measurement. Kept behind an env var so an ordinary `cargo build`
    // never drags the Ergo primitives into the guest ELF.
    let mut options = HashMap::new();
    if std::env::var("AEGIS_EPOCH_AUXPOW").as_deref() == Ok("1") {
        let epoch_opts = GuestOptionsBuilder::default()
            .features(vec!["aux-pow".to_string()])
            .build()
            .expect("guest options");
        // Keyed by the guest PACKAGE name (not the directory).
        options.insert("aegis_epoch_guest", epoch_opts);
    }

    embed_methods_with_options(options);
}
