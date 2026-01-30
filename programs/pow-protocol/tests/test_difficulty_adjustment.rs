#[cfg(test)]
mod tests {
    use super::*;

    // Constantes de test (copiées depuis constants.rs)
    const TARGET_BLOCK_TIME: i64 = 60;
    const MIN_DIFFICULTY: u128 = 1_000;
    const MAX_DIFFICULTY: u128 = u128::MAX / 1000;

    /// Simule la fonction adjust_difficulty du smart contract
    fn adjust_difficulty(current_difficulty: u128, delta_seconds: i64) -> u128 {
        let delta_u128 = delta_seconds.max(1) as u128;
        let target_u128 = TARGET_BLOCK_TIME as u128;

        // ratio en millièmes
        let ratio_x1000 = (delta_u128 * 1000) / target_u128;

        let (adjustment_num, adjustment_den): (u128, u128) = if ratio_x1000 < 500 {
            (2, 1)      // ×2.0
        } else if ratio_x1000 < 750 {
            (3, 2)      // ×1.5
        } else if ratio_x1000 < 900 {
            (11, 10)    // ×1.1
        } else if ratio_x1000 <= 1100 {
            (1, 1)      // ×1.0
        } else if ratio_x1000 <= 1500 {
            (9, 10)     // ×0.9
        } else if ratio_x1000 <= 2000 {
            (7, 10)     // ×0.7
        } else {
            (1, 2)      // ×0.5
        };

        let new_difficulty = (current_difficulty * adjustment_num) / adjustment_den;
        new_difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
    }

    #[test]
    fn test_very_fast_block() {
        // Bloc en 10s (target 60s) → devrait doubler
        let diff = 1_000_000;
        let new_diff = adjust_difficulty(diff, 10);
        assert_eq!(new_diff, 2_000_000);
    }

    #[test]
    fn test_fast_block() {
        // Bloc en 40s (target 60s) → devrait +50%
        let diff = 1_000_000;
        let new_diff = adjust_difficulty(diff, 40);
        assert_eq!(new_diff, 1_500_000);
    }

    #[test]
    fn test_slightly_fast_block() {
        // Bloc en 50s (target 60s) → devrait +10%
        let diff = 1_000_000;
        let new_diff = adjust_difficulty(diff, 50);
        assert_eq!(new_diff, 1_100_000);
    }

    #[test]
    fn test_target_block() {
        // Bloc en 60s (target 60s) → pas de changement
        let diff = 1_000_000;
        let new_diff = adjust_difficulty(diff, 60);
        assert_eq!(new_diff, 1_000_000);
    }

    #[test]
    fn test_slightly_slow_block() {
        // Bloc en 70s (target 60s) → devrait -10%
        let diff = 1_000_000;
        let new_diff = adjust_difficulty(diff, 70);
        assert_eq!(new_diff, 900_000);
    }

    #[test]
    fn test_slow_block() {
        // Bloc en 100s (target 60s) → devrait -30%
        let diff = 1_000_000;
        let new_diff = adjust_difficulty(diff, 100);
        assert_eq!(new_diff, 700_000);
    }

    #[test]
    fn test_very_slow_block() {
        // Bloc en 180s (target 60s) → devrait diviser par 2
        let diff = 1_000_000;
        let new_diff = adjust_difficulty(diff, 180);
        assert_eq!(new_diff, 500_000);
    }

    #[test]
    fn test_min_difficulty_clamp() {
        // Même avec division par 2, ne devrait pas descendre sous MIN
        let diff = 500;
        let new_diff = adjust_difficulty(diff, 180);
        assert_eq!(new_diff, MIN_DIFFICULTY);
    }

    #[test]
    fn test_convergence_simulation() {
        // Simuler une convergence avec hashrate constant
        const HASHRATE: u128 = 10_000_000_000; // 10 GH/s
        let mut difficulty = 1_000_000u128;
        let mut blocks = 0;

        // Simuler jusqu'à 100 blocs max
        for _ in 0..100 {
            // Temps de bloc = difficulté / hashrate
            let block_time = (difficulty / HASHRATE).max(1) as i64;

            // Ajuster
            difficulty = adjust_difficulty(difficulty, block_time);
            blocks += 1;

            // Vérifier si convergé (temps de bloc entre 54s et 66s)
            let final_time = (difficulty / HASHRATE) as i64;
            if final_time >= 54 && final_time <= 66 {
                println!("Convergence en {} blocs", blocks);
                println!("Difficulté finale: {}", difficulty);
                println!("Temps de bloc final: {}s", final_time);
                assert!(blocks < 50, "Devrait converger en moins de 50 blocs");
                return;
            }
        }

        panic!("Pas de convergence après 100 blocs");
    }

    #[test]
    fn test_no_overflow() {
        // Tester avec des grandes valeurs
        let diff = u128::MAX / 10_000;
        let new_diff = adjust_difficulty(diff, 10);
        assert!(new_diff <= MAX_DIFFICULTY);
        assert!(new_diff > MIN_DIFFICULTY);
    }
}
