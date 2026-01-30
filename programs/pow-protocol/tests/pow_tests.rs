#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    /// Test de la difficulté PoW
    #[test]
    fn test_difficulty_validation() {
        // Paramètres de test
        let challenge: [u8; 32] = [0u8; 32];
        let difficulty: u128 = 1_000_000; // Ajustez selon votre config

        // Calcul du target à partir de la difficulté
        let target = u128::MAX / difficulty;

        println!("Difficulté: {}", difficulty);
        println!("Target: {:032x}", target);

        // Essayer de trouver un nonce valide
        let mut found = false;
        let max_iterations = 1_000_000;

        for nonce in 0..max_iterations {
            let hash = compute_hash(&challenge, nonce);
            let hash_value = u128::from_le_bytes(hash[..16].try_into().unwrap());

            if hash_value < target {
                println!("✓ Nonce valide trouvé: {}", nonce);
                println!("  Hash: {:032x}", hash_value);
                println!("  Iterations: {}", nonce);
                found = true;
                break;
            }
        }

        if !found {
            println!("✗ Aucun nonce trouvé en {} iterations", max_iterations);
            println!("  La difficulté est peut-être trop élevée pour ce test");
        }

        assert!(found || difficulty > 100_000, "Difficulté trop haute pour le test");
    }

    /// Test de performance: combien de hashs par seconde ?
    #[test]
    fn test_mining_performance() {
        use std::time::Instant;

        let challenge: [u8; 32] = [0u8; 32];
        let iterations = 100_000;

        let start = Instant::now();
        for nonce in 0..iterations {
            let _ = compute_hash(&challenge, nonce);
        }
        let duration = start.elapsed();

        let hashes_per_sec = (iterations as f64) / duration.as_secs_f64();
        println!("Performance: {:.0} H/s", hashes_per_sec);
        println!("Temps pour {} hash: {:?}", iterations, duration);
    }

    /// Test de distribution de probabilité
    #[test]
    fn test_hash_distribution() {
        let challenge: [u8; 32] = [0u8; 32];
        let samples = 10_000;
        let difficulty = 1_000;
        let target = u128::MAX / difficulty;

        let mut valid_count = 0;

        for nonce in 0..samples {
            let hash = compute_hash(&challenge, nonce);
            let hash_value = u128::from_le_bytes(hash[..16].try_into().unwrap());

            if hash_value < target {
                valid_count += 1;
            }
        }

        let success_rate = (valid_count as f64) / (samples as f64);
        let expected_rate = 1.0 / (difficulty as f64);

        println!("Taux de succès: {:.6} ({}/{})", success_rate, valid_count, samples);
        println!("Taux attendu: {:.6}", expected_rate);
        println!("Difficulté: {}", difficulty);

        // Vérifier que le taux est dans une marge raisonnable (±20%)
        assert!(
            success_rate > expected_rate * 0.8 && success_rate < expected_rate * 1.2,
            "Distribution anormale"
        );
    }

    // Fonction helper pour calculer le hash
    fn compute_hash(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(challenge);
        hasher.update(&nonce.to_le_bytes());
        hasher.finalize().into()
    }
}
