//! Built-in lookup of common MAC address OUI prefixes to vendor names.
//!
//! The prefixes are a small, hand-curated subset of the IEEE MA-L registry
//! (<https://standards-oui.ieee.org/>) covering vendors that commonly show up on
//! home and office networks. Anything not listed returns `None`; the full
//! registry has tens of thousands of entries and is deliberately not bundled.

/// Look up the device vendor for a MAC address by its 24-bit OUI prefix.
///
/// Accepts any separator (`:`, `-`, `.`, or none) and either case. Returns
/// `None` for unknown prefixes or input shorter than six hex digits.
pub fn lookup_vendor(mac_str: &str) -> Option<&'static str> {
    // Keep only hex digits so odd separators or stray characters cannot shift
    // the prefix, and take exactly six of them (never slicing by byte offset).
    let prefix: String = mac_str
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_uppercase())
        .take(6)
        .collect();

    if prefix.len() < 6 {
        return None;
    }

    // Curated high-frequency vendor OUI map
    match prefix.as_str() {
        // Apple
        "0017F2" | "0019E3" | "001B63" | "001C42" | "001D4F" | "001E52" | "001F5B" | "0021E9"
        | "002241" | "002312" | "002332" | "00236C" | "002436" | "002500" | "00254B" | "002608"
        | "00264A" | "0026B0" | "3C0754" | "40A6D9" | "70CD60" | "7CE9D3" | "8C8590" | "A483E7"
        | "ACDE48" | "B8E856" | "C82A14" | "DC2B61" | "F4D488" | "F01898" | "F431C3" | "FCFC48"
        | "F0D5BF" | "9C04EB" | "B019C6" => Some("Apple, Inc."),
        // Raspberry Pi Foundation
        "B827EB" | "DCA632" | "E45F01" | "28CDC4" => Some("Raspberry Pi"),
        // Google / Nest
        "F4F5DB" | "546009" | "D86C63" | "3C5AB4" | "689A87" | "A47733" => Some("Google / Nest"),
        // Amazon
        "44650D" | "747548" | "FC65DE" | "68545A" | "38F7CD" | "AC63BE" | "50F5DA" => {
            Some("Amazon Technologies")
        }
        // Espressif (ESP8266 / ESP32 IoT devices)
        "240AC4" | "30AEA4" | "246F28" | "840D8E" | "A4CF12" | "3C71BF" | "807D3A" | "CC50E3"
        | "485519" | "DC5475" => Some("Espressif IoT"),
        // TP-Link
        "50C7BF" | "54AF97" | "60E327" | "90F652" | "C025E9" | "E848B8" | "EC086B" | "001D0F"
        | "0023CD" | "002586" => Some("TP-Link Technologies"),
        // Netgear
        "00146C" | "00184D" | "001E2A" | "001F33" | "0024B2" | "0026F2" | "204E7F" => {
            Some("Netgear")
        }
        // Cisco Systems
        "00000C" | "000142" | "000143" | "000163" | "000164" | "000196" | "000197" | "000216"
        | "000217" | "00024A" => Some("Cisco Systems"),
        // Intel
        "001B21" | "001E67" | "00215C" | "00216A" | "002314" | "0024D7" | "080046" | "6805CA"
        | "8086F2" => Some("Intel Corporate"),
        // Dell
        "001422" | "00188B" | "0019B9" | "001A4B" | "001C23" | "001D09" | "1866DA" | "70B5E8"
        | "B8AC6F" | "F04DA2" => Some("Dell Inc."),
        // HP
        "000E7F" | "001185" | "001279" | "001321" | "0014C2" | "001560" | "3C4A92" => {
            Some("HP Inc.")
        }
        // Samsung
        "0000F0" | "000278" | "0007AB" | "000D3A" | "001247" | "001599" | "342387" | "508569"
        | "946372" | "BC79AD" => Some("Samsung Electronics"),
        // Microsoft
        "00155D" | "00125A" | "0017FA" | "002248" | "0025AE" | "281878" | "6045BD" => {
            Some("Microsoft Corporation")
        }
        // Ubiquiti Networks
        "00156D" | "002722" | "24A43C" | "44D9E7" | "68D79A" | "7483C2" | "802AA8" => {
            Some("Ubiquiti Networks")
        }
        // Synology
        "001132" => Some("Synology Inc."),
        // ASUS
        "00112F" | "0013D4" | "0015F2" | "0018F3" | "001BFC" | "04D9F5" | "10BF48" => {
            Some("ASUSTeK Computer")
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::lookup_vendor;

    #[test]
    fn matches_known_prefix_regardless_of_separator_and_case() {
        for mac in [
            "B8:27:EB:12:34:56",
            "b8-27-eb-12-34-56",
            "b827.eb12.3456",
            "b827eb123456",
        ] {
            assert_eq!(lookup_vendor(mac), Some("Raspberry Pi"), "{mac}");
        }
    }

    #[test]
    fn unknown_prefix_is_none() {
        assert_eq!(lookup_vendor("FF:FF:FF:00:00:00"), None);
    }

    #[test]
    fn short_or_garbage_input_is_none() {
        assert_eq!(lookup_vendor(""), None);
        assert_eq!(lookup_vendor("B8:27"), None);
        assert_eq!(lookup_vendor("zz:zz:zz:zz:zz:zz"), None);
    }

    #[test]
    fn non_ascii_input_does_not_panic() {
        assert_eq!(lookup_vendor("ééééé"), None);
        assert_eq!(lookup_vendor("aaaaaé"), None);
    }
}
