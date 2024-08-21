use dane_updater::load_pubkey;

#[test]
fn test_load_pubkey() {
    let prime256v1_expected = "3059301306072a8648ce3d020106082a\
                               8648ce3d030107034200040e2e2e480b\
                               9de56452c391b447e077de94e5045052\
                               3ed4b24aadb291e86d963f90dd91b55b\
                               a62ce3e21ed477e0dfc003b2b7517c86\
                               fce5e3373f9bd99365d7dc";

    let secp384r1_expected = "3076301006072a8648ce3d020106052b8\
                              104002203620004b7307051a7cc630dd9\
                              cc618a0297ea26d35a3da0b16dc7113ab\
                              ed6ce3ccb1507ba25f35821d7109494c8\
                              a10ac6ceaf81bc68a3c1fafcae3a7838a\
                              a1b3bf25bb12f6884a48edc26c1e04705\
                              055cb4c2fc2b8c17faec44d694df9c0d2\
                              61cf32abf";

    for (filename, expected) in [
        ("test_data/prime256v1.pem", prime256v1_expected),
        ("test_data/secp384r1.pem", secp384r1_expected),
    ] {
        let key = load_pubkey(filename).unwrap();
        assert_eq!(key, base16::decode(expected).unwrap());
    }
}
