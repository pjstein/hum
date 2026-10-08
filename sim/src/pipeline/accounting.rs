//! zCDP accounting, ported one-to-one from the research code.

/// δ used everywhere in draft 0.1.
pub const DELTA: f64 = 1e-6;

/// Largest ρ such that ρ-zCDP implies (ε, δ)-DP, from ε = ρ + 2√(ρ ln(1/δ)).
pub fn eps_to_rho(eps: f64, delta: f64) -> f64 {
    if eps.is_infinite() {
        return f64::INFINITY;
    }
    let l = (1.0 / delta).ln();
    let s = f64::midpoint(-2.0 * l.sqrt(), (4.0 * l + 4.0 * eps).sqrt());
    s * s
}

/// ε implied by ρ-zCDP at δ.
pub fn rho_to_eps(rho: f64, delta: f64) -> f64 {
    rho + 2.0 * (rho * (1.0 / delta).ln()).sqrt()
}

/// Gaussian noise scale for an L2 sensitivity at ρ. Zero when ρ is infinite.
pub fn gauss_sigma(l2_sens: f64, rho: f64) -> f64 {
    if rho.is_infinite() {
        0.0
    } else {
        l2_sens / (2.0 * rho).sqrt()
    }
}

/// Budget split between the four release parts (`DEFAULT_SPLIT`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Split {
    /// Statement tallies.
    pub tally: f64,
    /// Covariance.
    pub cov: f64,
    /// Opinion map histogram.
    pub hist: f64,
    /// Per-group tallies.
    pub group: f64,
}

/// The research default: 0.15 / 0.35 / 0.15 / 0.35.
pub const DEFAULT_SPLIT: Split = Split {
    tally: 0.15,
    cov: 0.35,
    hist: 0.15,
    group: 0.35,
};

/// Everything on tallies, for a tallies-only release.
pub const TALLIES_ONLY: Split = Split {
    tally: 1.0,
    cov: 0.0,
    hist: 0.0,
    group: 0.0,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eps_4_is_rho_0_254() {
        let rho = eps_to_rho(4.0, DELTA);
        assert!((rho - 0.254).abs() < 0.001, "rho = {rho}");
        assert!((rho_to_eps(rho, DELTA) - 4.0).abs() < 1e-9);
    }

    #[test]
    fn eps_8_is_rho_0_91() {
        assert!((eps_to_rho(8.0, DELTA) - 0.91).abs() < 0.005);
    }

    #[test]
    fn four_releases_at_eps_4_compose_to_about_8_5() {
        let total = 4.0 * eps_to_rho(4.0, DELTA);
        let eps = rho_to_eps(total, DELTA);
        assert!((eps - 8.5).abs() < 0.1, "eps = {eps}");
    }

    #[test]
    fn infinite_eps_means_no_noise() {
        assert_eq!(gauss_sigma(3.0, eps_to_rho(f64::INFINITY, DELTA)), 0.0);
    }
}
