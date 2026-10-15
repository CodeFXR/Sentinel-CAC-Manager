use regex::Regex;

/// Checks if an ATR matches known DoD CAC or PIV smart card profiles.
pub fn is_cac_or_piv_atr(raw_atr: &str) -> bool {
    let clean = raw_atr.replace([':', ' ', '-'], "").to_lowercase();
    // Known historical and modern CAC / PIV ATR prefixes
    // 3b7d96000080318065b0... (Oberthur ID-One PIV)
    // 3bdb9600801f030031c0... (Gemalto TOP DL GX4)
    // 3b7b940000... (G&D SmartCafe Expert)
    // 3b7d940000...
    clean.starts_with("3b7d96")
        || clean.starts_with("3bdb96")
        || clean.starts_with("3b7b94")
        || clean.starts_with("3b7d94")
        || clean.starts_with("3bf818")
        || clean.starts_with("3bfa18")
}

/// Parses the output of `pkcs15-tool -c` into (id, label) tuples.
pub fn parse_pkcs15_tool_list(output: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut current_id = None;
    let mut current_label = None;

    let re_id = Regex::new(r"^\s*ID\s*:\s*([a-fA-F0-9]+)").unwrap();
    let re_label = Regex::new(r"^\s*Label\s*:\s*(.+)").unwrap();

    for line in output.lines() {
        if let Some(caps) = re_id.captures(line) {
            current_id = Some(caps[1].trim().to_string());
        } else if let Some(caps) = re_label.captures(line) {
            current_label = Some(caps[1].trim().to_string());
        }

        if let (Some(id), Some(label)) = (current_id.as_ref(), current_label.as_ref()) {
            pairs.push((id.clone(), label.clone()));
            current_id = None;
            current_label = None;
        }
    }

    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atr_detection() {
        assert!(is_cac_or_piv_atr("3b:7d:96:00:00:80:31:80:65:b0:75:49:17:0f:83:00:90:00"));
        assert!(!is_cac_or_piv_atr("3b:00:00:00"));
    }
}
