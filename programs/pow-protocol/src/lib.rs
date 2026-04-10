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

#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Hashish PoW Protocol",
    project_url: "https://hashish.fun",
    contacts: "email:admin@hashish.fun",
    policy: "https://github.com/Hashishdotfun/PoW-Programs/blob/main/SECURITY.md",
    preferred_languages: "en,fr",
    source_code: "https://github.com/Hashishdotfun/PoW-Programs",
    auditors: "N/A"
}

pub mod constants;
pub mod errors;
pub mod state;
pub mod instructions;

use instructions::*;

declare_id!("PoWQ79wY7LXrKaU8vZBoFb4JgSytENSdpAQAPJaZiSh");

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
    pub fn initialize(ctx: Context<Initialize>, pool_id: u8) -> Result<()> {
        instructions::initialize::handler(ctx, pool_id)
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
    // ATTESTATION DEVICE
    // =========================================================================

    /// Crée ou rafraîchit une attestation device
    ///
    /// Le backend vérifie le hardware TEE du Seeker, puis co-signe cette
    /// transaction. L'attestation est valide 60 secondes on-chain.
    /// Le miner paie le rent (première fois) et les tx fees.
    /// Quand l'attestation est consommée, son rent est renvoyé au `rent_recipient`.
    pub fn create_attestation(ctx: Context<CreateAttestation>) -> Result<()> {
        instructions::create_attestation::handler(ctx)
    }

    /// Ferme une attestation device à la fin d'une session de mining.
    /// Le rent de l'attestation est envoyé au `rent_recipient` enregistré.
    pub fn close_attestation(ctx: Context<CloseAttestation>) -> Result<()> {
        instructions::close_attestation::handler(ctx)
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

    /// Enregistre les tokens brûlés via le treasury buyback
    ///
    /// Diminue total_supply_mined pour libérer du cap supply.
    /// Callable par le programme pow-treasury uniquement.
    pub fn record_treasury_burn(ctx: Context<RecordTreasuryBurn>, amount: u64) -> Result<()> {
        instructions::update_config::record_treasury_burn(ctx, amount)
    }

    // =========================================================================
    // FEE DISTRIBUTION
    // =========================================================================

    /// Distribue les fees SOL du fee_collector
    ///
    /// Permissionless. 5% team, 95% direct vers treasury_sol_vault.
    pub fn distribute_fees(ctx: Context<DistributeFees>) -> Result<()> {
        instructions::distribute_fees::handler(ctx)
    }

    // =========================================================================
    // TRANSFER FEE COLLECTION (replaces transfer-hook)
    // =========================================================================

    /// Initialize the fee token vault for SPL2022 transfer fee collection.
    ///
    /// Authority only. Called once after deployment.
    /// After calling this, set the mint's withdrawWithheldAuthority
    /// to the fee_authority PDA using spl-token authorize.
    pub fn initialize_fee_vault(ctx: Context<InitializeFeeVault>) -> Result<()> {
        instructions::initialize_fee_vault::handler(ctx)
    }

    /// Collect and distribute SPL2022 transfer fees.
    ///
    /// Permissionless with cranker incentive (1% minted as HASHISH).
    /// 1. Harvest withheld fees from token accounts (remaining_accounts)
    /// 2. Withdraw fees from mint to fee_token_vault
    /// 3. Burn 50% (permanent deflation, frees supply cap)
    /// 4. Add 50% to pending miner rewards
    /// 5. Mint cranker reward
    pub fn collect_transfer_fees<'info>(
        ctx: Context<'_, '_, '_, 'info, CollectTransferFees<'info>>,
    ) -> Result<()> {
        instructions::collect_transfer_fees::handler(ctx)
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
        // Test reward pendant le boost (1ère année) - halved for dual pool
        let reward_boost = R0_BOOST;
        assert_eq!(reward_boost, 44_350_000); // 0.04435 tokens (half of 0.0887)

        // Test reward normal - halved for dual pool
        let reward_normal = R0_NORMAL;
        assert_eq!(reward_normal, 28_700_000); // 0.0287 tokens (half of 0.0574)
    }

    #[test]
    fn test_fee_calculation() {
        // Test fee initiale (0.001 SOL)
        assert_eq!(FEE_INITIAL_SOL, 1_000_000); // 0.001 SOL

        // Test fee après 2 ans (1.5x)
        let fee_2y = FEE_INITIAL_SOL * FEE_MULTIPLIER_NUMERATOR / FEE_MULTIPLIER_DENOMINATOR;
        assert_eq!(fee_2y, 1_500_000); // 0.0015 SOL

        // Test fee cap
        assert_eq!(FEE_SOL_CAP, 500_000_000); // 0.5 SOL
    }

}
