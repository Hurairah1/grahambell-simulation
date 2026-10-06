//! Rendering of the parameter registry for `gb params` and `parameters.csv`.

use gb_config::registry::ParamListing;

/// Output format for the parameter listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ListingFormat {
    /// Markdown table.
    Markdown,
    /// Comma-separated values.
    Csv,
}

/// Renders the parameter listing in the requested format.
pub fn render_listing(listing: &[ParamListing], format: ListingFormat) -> anyhow::Result<String> {
    match format {
        ListingFormat::Markdown => Ok(render_markdown(listing)),
        ListingFormat::Csv => render_csv(listing),
    }
}

fn render_markdown(listing: &[ParamListing]) -> String {
    let mut text = String::from(
        "| Key | Value | Status | Sweep | Unit | SPEC | Description |\n|---|---|---|---|---|---|---|\n",
    );
    for row in listing {
        text.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} |\n",
            row.key,
            escape(&row.value),
            row.status,
            escape(&row.sweep),
            row.unit,
            row.spec_ref,
            row.description
        ));
    }
    text
}

/// Writes the listing as CSV.
pub fn render_csv(listing: &[ParamListing]) -> anyhow::Result<String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    for row in listing {
        writer.serialize(row)?;
    }
    Ok(String::from_utf8(writer.into_inner()?)?)
}

fn escape(text: &str) -> String {
    text.replace('|', "\\|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use gb_config::Config;
    use gb_config::registry::parameter_listing;

    #[test]
    fn markdown_listing_has_one_row_per_parameter() {
        let listing = parameter_listing(&Config::default()).unwrap();
        let text = render_listing(&listing, ListingFormat::Markdown).unwrap();
        assert_eq!(text.lines().count(), listing.len() + 2);
        assert!(text.contains("`genesis.ids` | 2900000 | D"));
    }

    #[test]
    fn csv_listing_has_a_header_and_one_row_per_parameter() {
        let listing = parameter_listing(&Config::default()).unwrap();
        let text = render_listing(&listing, ListingFormat::Csv).unwrap();
        assert!(text.starts_with("key,status,value,sweep,unit,spec_ref,description"));
        let mut reader = csv::Reader::from_reader(text.as_bytes());
        assert_eq!(reader.records().count(), listing.len());
    }
}
