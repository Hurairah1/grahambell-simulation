//! The [`Param`] wrapper: a parameter value together with its SPEC status tag and sweep.
//!
//! SPEC section 2 tags every parameter as decided (`D`), proposed (`P`) or open (`O`), and
//! many rows list a sweep range or comparison variants. Keeping all three next to the value
//! means a run log records not just what was used, but how settled each choice is.

use serde::{Deserialize, Serialize};

/// Status tag of a parameter, as defined in the SPEC status legend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Status {
    /// Decided by the protocol architect.
    D,
    /// Proposed during design review; implemented so it can be compared with its alternative.
    P,
    /// Open: an undecided value or rule that is swept.
    O,
}

impl Status {
    /// The single-letter tag used in SPEC tables.
    pub fn tag(self) -> &'static str {
        match self {
            Status::D => "D",
            Status::P => "P",
            Status::O => "O",
        }
    }

    /// Plain-English meaning of the tag.
    pub fn meaning(self) -> &'static str {
        match self {
            Status::D => "decided",
            Status::P => "proposed (compare against the named alternative)",
            Status::O => "open (sweep it)",
        }
    }
}

/// Values or range over which a parameter is swept or compared.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sweep<T> {
    /// Explicit values to sweep or compare (may include the default).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<T>,
    /// Inclusive `[min, max]` range when the SPEC gives a range rather than a list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<[T; 2]>,
    /// Free-text note, for example the purpose of a comparison variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl<T> Sweep<T> {
    /// A sweep over an explicit list of values.
    pub fn values(values: Vec<T>) -> Self {
        Sweep {
            values,
            range: None,
            note: None,
        }
    }

    /// A sweep over an inclusive range.
    pub fn range(min: T, max: T) -> Self {
        Sweep {
            values: Vec::new(),
            range: Some([min, max]),
            note: None,
        }
    }

    /// Attaches an explanatory note to the sweep.
    pub fn with_note(mut self, note: &str) -> Self {
        self.note = Some(note.to_string());
        self
    }
}

/// A configurable parameter: its value, its SPEC status tag and an optional sweep.
///
/// A value of type `Option<_>` that is `None` represents a SPEC default of "—" (not yet
/// chosen); such parameters are only ever used through their sweep.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Param<T> {
    /// The value used by default.
    #[serde(default)]
    pub value: T,
    /// SPEC status tag. A configuration file may restate it but may not change it.
    pub status: Status,
    /// Sweep or comparison values, when the SPEC lists any.
    #[serde(default = "Option::default", skip_serializing_if = "Option::is_none")]
    pub sweep: Option<Sweep<T>>,
}

impl<T> Param<T> {
    /// A decided parameter with no sweep.
    pub fn decided(value: T) -> Self {
        Param {
            value,
            status: Status::D,
            sweep: None,
        }
    }

    /// A parameter with the given status and no sweep.
    pub fn with_status(value: T, status: Status) -> Self {
        Param {
            value,
            status,
            sweep: None,
        }
    }

    /// Adds a sweep to the parameter.
    pub fn swept(mut self, sweep: Sweep<T>) -> Self {
        self.sweep = Some(sweep);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Holder {
        a: Param<f64>,
        b: Param<Option<f64>>,
    }

    #[test]
    fn status_tags_round_trip_through_toml() {
        let holder = Holder {
            a: Param::with_status(10.0, Status::O).swept(Sweep::range(1.0, 10.0)),
            b: Param::with_status(None, Status::O).swept(Sweep::values(vec![Some(3600.0)])),
        };
        let text = toml::to_string(&holder).unwrap();
        let back: Holder = toml::from_str(&text).unwrap();
        assert_eq!(back, holder);
    }

    #[test]
    fn unset_optional_value_is_omitted_and_read_back_as_none() {
        let holder = Holder {
            a: Param::decided(1.0),
            b: Param::with_status(None, Status::O),
        };
        let text = toml::to_string(&holder).unwrap();
        assert!(!text.contains("b.value") && !text.contains("value = nan"));
        let back: Holder = toml::from_str(&text).unwrap();
        assert_eq!(back.b.value, None);
    }

    #[test]
    fn status_meanings_match_spec_legend() {
        assert_eq!(Status::D.tag(), "D");
        assert_eq!(Status::P.tag(), "P");
        assert_eq!(Status::O.tag(), "O");
        assert!(Status::O.meaning().contains("sweep"));
    }

    #[test]
    fn sweep_note_is_attached() {
        let sweep = Sweep::values(vec![3_u32, 2]).with_note("30-node comparison");
        assert_eq!(sweep.note.as_deref(), Some("30-node comparison"));
    }
}
