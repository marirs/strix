//! Optional .sng count-model scoring. Loading allocates once; scoring does not
//! allocate, normalize a String, or change the borrowed extraction result.
//! Scores are mean log10 likelihoods, not Ghidra acceptance thresholds.
use crate::{Error, Result};
use std::collections::HashMap;

/// Shared probabilistic trigram model loaded from tab-separated .sng counts.
#[derive(Debug, Clone)]
pub struct TrigramModel {
    probabilities: HashMap<[u8; 3], f64>,
    unseen: f64,
    lowercase: bool,
}
impl TrigramModel {
    /// Parse model rows (`character TAB character TAB character TAB count`).
    /// Supports ASCII, [SP], [HT], [^] and [$]. No model is downloaded implicitly.
    pub fn from_sng(text: &str) -> Result<Self> {
        let mut counts = HashMap::<[u8; 3], f64>::new();
        let mut lowercase = false;
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            if line == "#" || line.starts_with("# ") {
                if let Some((_, kind)) = line.split_once("Model Type:") {
                    lowercase = kind.trim().eq_ignore_ascii_case("lowercase");
                }
                continue;
            }
            let error = || Error::Other(format!("invalid .sng row {}", index + 1));
            let mut parts = line.split('\t');
            let mut key = [0; 3];
            for value in &mut key {
                let token = parts.next().ok_or_else(error)?;
                *value = match token {
                    "[^]" => 128,
                    "[$]" => 129,
                    "[SP]" => b' ',
                    "[HT]" => b'\t',
                    _ if token.len() == 1 && token.is_ascii() => token.as_bytes()[0],
                    _ => return Err(error()),
                };
            }
            let count: u64 = parts
                .next()
                .ok_or_else(error)?
                .parse()
                .map_err(|_| error())?;
            if parts.next().is_some() {
                return Err(error());
            }
            // Zero-count rows are smoothed to one, matching the .sng convention.
            *counts.entry(key).or_default() += count.max(1) as f64;
        }
        if counts.is_empty() {
            return Err(Error::Other("empty .sng model".into()));
        }
        let total: f64 = counts.values().sum::<f64>() + 130f64.powi(3);
        let unseen = (1.0 / total).log10();
        Ok(Self {
            probabilities: counts
                .into_iter()
                .map(|(k, n)| (k, ((n + 1.0) / total).log10()))
                .collect(),
            unseen,
            lowercase,
        })
    }
    /// Average log10 probability for ASCII text of at least three characters.
    /// Non-ASCII returns None instead of deleting or transliterating content.
    pub fn score(&self, text: &str) -> Option<f64> {
        if !text.is_ascii() {
            return None;
        }
        let mut previous = [128u8, 128];
        let mut len = 0;
        let mut terms = 0;
        let mut sum = 0.0;
        for mut byte in text.bytes() {
            if self.lowercase {
                byte = byte.to_ascii_lowercase();
            }
            if len >= 1 {
                let key = [previous[0], previous[1], byte];
                sum += self.probabilities.get(&key).copied().unwrap_or(self.unseen);
                terms += 1;
            }
            previous = [previous[1], byte];
            len += 1;
        }
        if len < 3 {
            return None;
        }
        sum += self
            .probabilities
            .get(&[previous[0], previous[1], 129])
            .copied()
            .unwrap_or(self.unseen);
        Some(sum / (terms + 1) as f64)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn corpus_score_preserves_text_and_distinguishes_noise() {
        let model=TrigramModel::from_sng("# Model Type: lowercase\n[^]\th\te\t100\nh\te\tl\t100\ne\tl\tl\t100\nl\tl\to\t100\nl\to\t[$]\t100\nx\ty\tz\t1").unwrap();
        assert!(model.score("hello") > model.score("qzxvk"));
        assert_eq!(model.score("HELLO"), model.score("hello"));
        assert_eq!(model.score("你好世界"), None);
        assert_eq!(model.score("hi"), None);
        assert!(TrigramModel::from_sng("oops").is_err());
        assert!(TrigramModel::from_sng("").is_err());
    }
}
