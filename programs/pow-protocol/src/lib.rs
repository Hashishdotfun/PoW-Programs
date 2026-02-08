// =============================================================================
// POW PROTOCOL - Smart Contract Principal
// =============================================================================
// Un système de Proof of Work moderne sur Solana avec:
// - Mining off-chain, vérification on-chain
// - Reward décroissant (exponentiel) avec boost première année
// - Fee SOL progressive (×1.5 tous les 2 ans)
// - Distribution automatique: Team 5%, Protocol 95% (Buyback + LP)
// - Intégration avec taxe SPL2022 (0.01%: 50% burn, 50% mineurs)
// - Difficulté dynamique basée sur le block time

use anchor_lang::prelude::*;

pub mod constants;
pub mod errors;
pub mod state;
pub mod instructions;

use instructions::*;

declare_id!("6DEmqXKEokfBz2wiREVthwbkDECvrWorkJNd48duatL2");

#[program]
pub mod pow_protocol {
    use super::*;

    // =========================================================================
    // INITIALISATION
    // =========================================================================

    /// Initialise le protocole PoW
    /// 
    /// Doit être appelé une seule fois après le déploiement.
    /// Configure tous les paramètres et crée les PDAs nécessaires.
    /// 
    /// # Arguments
    /// Aucun - tous les paramètres sont définis dans constants.rs
    /// 
    /// # Accounts
    /// - `authority`: Le déployeur qui devient l'admin
    /// - `mint`: Le token SPL2022 à miner
    /// - `pow_config`: PDA de configuration (créé)
    /// - `pow_vault`: PDA pour les tokens de reward (créé)
    /// - `team_vault`: PDA pour les fees team (créé)
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize::handler(ctx)
    }

    // =========================================================================
    // MINING
    // =========================================================================

    /// Soumet une preuve de travail valide
    /// 
    /// Le mineur doit trouver un nonce tel que:
    /// `hash(challenge || nonce) < target`
    /// 
    /// Si la preuve est valide:
    /// 1. Le mineur paie la fee en SOL
    /// 2. Le mineur reçoit le reward (base + pending de la taxe transfert)
    /// 3. La difficulté est ajustée selon le temps écoulé
    /// 4. Un nouveau challenge est généré
    /// 
    /// # Arguments
    /// - `nonce`: Le nonce trouvé par le mineur
    /// 
    /// # Accounts
    /// - `miner`: Le mineur qui soumet la preuve
    /// - `miner_token_account`: Token account du mineur (reçoit le reward)
    /// - `miner_stats`: Stats du mineur (créé si nécessaire)
    /// - `pow_config`: Configuration du protocole
    /// - `mint`: Le token SPL2022
    /// - `fee_collector`: PDA qui collecte les fees
    pub fn submit_proof(ctx: Context<SubmitProof>, nonce: u128) -> Result<()> {
        instructions::submit_proof::handler(ctx, nonce)
    }

    // =========================================================================
    // DISTRIBUTION DES FEES
    // =========================================================================

    /// Distribue les fees SOL accumulées
    /// 
    /// Permissionless - n'importe qui peut appeler cette instruction.
    /// Distribue selon le modèle:
    /// - 5% → Team vault
    /// - 57% → Buyback (60% * 95%)
    /// - 38% → LP direct (40% * 95%)
    /// 
    /// # Accounts
    /// - `fee_collector`: PDA avec les fees accumulées
    /// - `team_vault`: Reçoit 5%
    /// - `buyback_vault`: Reçoit 57% (pour swap SOL→Token)
    /// - `lp_vault`: Reçoit 38% (pour add liquidity)
    pub fn distribute_fees(ctx: Context<DistributeFees>) -> Result<()> {
        instructions::distribute_fees::handler(ctx)
    }

    // ==========================================================================
    // BUYBACK - Traitement des tokens achetés
    // ==========================================================================

    /// Traite les tokens achetés via buyback off-chain
    ///
    /// Le swap SOL → Token est fait off-chain via script TypeScript.
    /// Cette instruction traite les tokens reçus:
    /// - 50% sont brûlés
    /// - 50% restent pour LP
    ///
    /// Permissionless - n'importe qui peut appeler.
    pub fn execute_buyback(ctx: Context<ExecuteBuyback>) -> Result<()> {
        instructions::distribute_fees::execute_buyback(ctx)
    }

    /// Retire le SOL du buyback_vault vers le keeper pour le swap off-chain
    ///
    /// Permissionless - le keeper fait le swap puis appelle execute_buyback
    pub fn withdraw_for_buyback(ctx: Context<WithdrawForBuyback>) -> Result<()> {
        instructions::distribute_fees::withdraw_for_buyback(ctx)
    }

    /// Retire le SOL du lp_vault vers le keeper pour ajouter de la liquidité
    ///
    /// Permissionless - le keeper ajoute la liquidité puis burn les LP tokens
    pub fn withdraw_for_lp(ctx: Context<WithdrawForLp>) -> Result<()> {
        instructions::distribute_fees::withdraw_for_lp(ctx)
    }

    // =========================================================================
    // ADMINISTRATION
    // =========================================================================

    /// Met à jour la configuration du protocole
    /// 
    /// Seule l'autorité peut appeler cette instruction.
    /// Certains paramètres sont immuables pour garantir la confiance.
    /// 
    /// # Arguments
    /// - `params`: Paramètres à mettre à jour (optionnels)
    pub fn update_config(ctx: Context<UpdateConfig>, params: UpdateConfigParams) -> Result<()> {
        instructions::update_config::handler(ctx, params)
    }

    /// Transfère l'autorité à une nouvelle adresse
    /// 
    /// Sécurité: les deux autorités (ancienne et nouvelle) doivent signer
    pub fn transfer_authority(ctx: Context<TransferAuthority>) -> Result<()> {
        instructions::update_config::transfer_authority(ctx)
    }

    /// Retire les fees accumulées pour la team
    /// 
    /// Seule l'autorité peut retirer les fees.
    /// 
    /// # Arguments
    /// - `amount`: Montant à retirer (None = tout)
    pub fn claim_team_fees(ctx: Context<ClaimTeamFees>, amount: Option<u64>) -> Result<()> {
        instructions::claim_team_fees::handler(ctx, amount)
    }

    // =========================================================================
    // INTÉGRATION TRANSFER HOOK (SPL2022)
    // =========================================================================

    /// Ajoute des tokens au pool de pending reward
    /// 
    /// Appelé par le programme transfer hook quand la taxe est collectée.
    /// 50% de la taxe va ici (les autres 50% sont brûlés par le hook).
    /// 
    /// # Arguments
    /// - `amount`: Montant de tokens à ajouter
    pub fn add_pending_reward(ctx: Context<AddPendingReward>, amount: u64) -> Result<()> {
        instructions::update_config::add_pending_reward(ctx, amount)
    }

    /// Enregistre les tokens brûlés via la taxe transfert
    /// 
    /// Pour le tracking et les stats.
    /// 
    /// # Arguments
    /// - `amount`: Montant brûlé
    pub fn record_transfer_burn(ctx: Context<RecordTransferBurn>, amount: u64) -> Result<()> {
        instructions::update_config::record_transfer_burn(ctx, amount)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::*;
    use solana_program::hash::hash;

    #[test]
    fn test_proof_verification() {
        // Créer un challenge de test
        let challenge: [u8; 32] = [1u8; 32];
        let difficulty: u128 = 1_000;
        
        // Calculer le target
        let target = u128::MAX / difficulty;
        
        // Tester avec différents nonces
        for nonce in 0..1000u64 {
            let mut message = Vec::with_capacity(40);
            message.extend_from_slice(&challenge);
            message.extend_from_slice(&nonce.to_le_bytes());
            
            let hash_result = hash(&message);
            let hash_bytes = hash_result.to_bytes();
            let hash_value = u128::from_le_bytes(hash_bytes[..16].try_into().unwrap());
            
            if hash_value < target {
                println!("Found valid nonce: {} (hash: {})", nonce, hash_value);
                break;
            }
        }
    }

    #[test]
    fn test_reward_calculation() {
        // Test reward pendant le boost (1ère année)
        let reward_boost = R0_BOOST;
        assert_eq!(reward_boost, 88_700_000); // 0.0887 tokens

        // Test reward normal
        let reward_normal = R0_NORMAL;
        assert_eq!(reward_normal, 57_400_000); // 0.0574 tokens
    }

    #[test]
    fn test_fee_calculation() {
        // Test fee initiale
        assert_eq!(FEE_INITIAL_SOL, 5_000_000); // 0.005 SOL

        // Test fee après 2 ans (1.5x)
        let fee_2y = FEE_INITIAL_SOL * FEE_MULTIPLIER_NUMERATOR / FEE_MULTIPLIER_DENOMINATOR;
        assert_eq!(fee_2y, 7_500_000); // 0.0075 SOL

        // Test fee cap
        assert_eq!(FEE_SOL_CAP, 50_000_000); // 0.05 SOL
    }

    #[test]
    fn test_difficulty_adjustment() {
        let initial_diff: u128 = 1_000_000;
        
        // Test augmentation (bloc trop rapide)
        let fast_diff = initial_diff * DIFF_UP_FACTOR_NUMERATOR / DIFF_UP_FACTOR_DENOMINATOR;
        assert_eq!(fast_diff, 1_020_000); // +2%

        // Test diminution (bloc trop lent)
        let slow_diff = initial_diff * DIFF_DOWN_FACTOR_NUMERATOR / DIFF_DOWN_FACTOR_DENOMINATOR;
        assert_eq!(slow_diff, 980_000); // -2%
    }
}
