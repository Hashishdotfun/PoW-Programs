// =============================================================================
// TRANSFER HOOK PROGRAM
// =============================================================================
// Programme séparé qui gère la taxe de transfert SPL2022 (0.01%)
// - 50% des taxes sont brûlées
// - 50% vont au pool de reward des mineurs (splitté 50/50 normal + seeker
//   via CPI pow-protocol::add_pending_reward)
//
// Ce programme est appelé automatiquement par SPL Token-2022 à chaque transfert

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};
use spl_transfer_hook_interface::instruction::{ExecuteInstruction, TransferHookInstruction};
use spl_tlv_account_resolution::{
    account::ExtraAccountMeta,
    seeds::Seed,
    state::ExtraAccountMetaList,
};

declare_id!("95zaGUMvrNFnCpjSqQyTNw3msyJtj9drQ5mWYm1eP6S3");

// =============================================================================
// CONSTANTES
// =============================================================================

/// Seed pour le PDA extra account metas
pub const EXTRA_ACCOUNT_METAS_SEED: &[u8] = b"extra-account-metas";

/// Seed pour le fee vault
pub const FEE_VAULT_SEED: &[u8] = b"fee_vault";

/// Seed pour le PoW config (dans le programme PoW)
pub const POW_CONFIG_SEED: &[u8] = b"pow_config";

/// Taxe en basis points (1 = 0.01%)
pub const TRANSFER_TAX_BPS: u64 = 1;

/// Pourcentage burn (50%)
pub const BURN_PERCENT: u64 = 50;

/// Pourcentage pour mineurs (50%)
pub const MINER_PERCENT: u64 = 50;

/// Cranker reward: 0.01% = 1 basis point
pub const CRANKER_REWARD_BPS: u64 = 1;

/// BPS denominator
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Pool IDs (same as pow-protocol constants)
pub const POOL_NORMAL: u8 = 0;
pub const POOL_SEEKER: u8 = 1;

/// Seed pour le mint authority (dans pow-protocol)
pub const MINT_AUTHORITY_SEED: &[u8] = b"pow_mint_auth";

// =============================================================================
// PROGRAMME
// =============================================================================

#[program]
pub mod transfer_hook {
    use super::*;

    /// Initialise les extra account metas requis par le hook
    ///
    /// Cette instruction doit être appelée UNE SEULE FOIS après la création du mint.
    /// Elle configure les comptes additionnels nécessaires pour chaque transfert.
    ///
    /// # Comptes additionnels configurés
    /// 1. `fee_vault` - Token account qui accumule les fees (PDA)
    /// 2. `pow_config` - Config du protocole PoW pour mettre à jour pending_reward
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
        pow_program_id: Pubkey,
    ) -> Result<()> {
        // Définir les extra accounts nécessaires pour chaque transfert
        let account_metas = vec![
            // 1. Fee Vault (PDA de CE programme)
            // C'est ici que les fees sont accumulées avant distribution
            ExtraAccountMeta::new_with_seeds(
                &[
                    Seed::Literal {
                        bytes: FEE_VAULT_SEED.to_vec(),
                    },
                    Seed::AccountKey { index: 1 }, // index 1 = mint
                ],
                false, // is_signer
                true,  // is_writable
            )?,

            // 2. PoW Config (PDA du programme PoW)
            // Pour mettre à jour pending_reward_tokens
            ExtraAccountMeta::new_with_seeds(
                &[
                    Seed::Literal {
                        bytes: POW_CONFIG_SEED.to_vec(),
                    },
                ],
                false, // is_signer
                true,  // is_writable
            )?,

            // 3. Token Program (pour le burn)
            ExtraAccountMeta::new_with_pubkey(&anchor_spl::token_2022::ID, false, false)?,

            // 4. PoW Program ID (pour CPI)
            ExtraAccountMeta::new_with_pubkey(&pow_program_id, false, false)?,
        ];

        // Calculer la taille nécessaire
        let account_size = ExtraAccountMetaList::size_of(account_metas.len())?;

        // Obtenir le rent minimum
        let lamports = Rent::get()?.minimum_balance(account_size);

        // Seeds pour signer
        let mint_key = ctx.accounts.mint.key();
        let signer_seeds: &[&[&[u8]]] = &[&[
            EXTRA_ACCOUNT_METAS_SEED,
            mint_key.as_ref(),
            &[ctx.bumps.extra_account_meta_list],
        ]];

        // Créer le compte
        anchor_lang::system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.extra_account_meta_list.to_account_info(),
                },
                signer_seeds,
            ),
            lamports,
            account_size as u64,
            &crate::ID,
        )?;

        // Initialiser la liste
        let mut data = ctx.accounts.extra_account_meta_list.try_borrow_mut_data()?;
        ExtraAccountMetaList::init::<ExecuteInstruction>(&mut data, &account_metas)?;

        // Sauvegarder le PoW program ID dans notre config
        let hook_config = &mut ctx.accounts.hook_config;
        hook_config.mint = ctx.accounts.mint.key();
        hook_config.pow_program_id = pow_program_id;
        hook_config.total_fees_collected = 0;
        hook_config.total_burned = 0;
        hook_config.total_to_miners = 0;
        hook_config.bump = ctx.bumps.hook_config;

        msg!("Transfer Hook initialized!");
        msg!("Mint: {}", ctx.accounts.mint.key());
        msg!("PoW Program: {}", pow_program_id);
        msg!("Extra Account Meta List: {}", ctx.accounts.extra_account_meta_list.key());

        Ok(())
    }

    /// Point d'entrée du Transfer Hook
    ///
    /// Cette fonction est appelée AUTOMATIQUEMENT par SPL Token-2022
    /// à chaque transfert de token.
    ///
    /// NOTE IMPORTANTE: Le Transfer Hook est appelé APRÈS le transfert.
    /// La fee a déjà été prélevée par le Transfer Fee Extension.
    /// Ici, on gère juste le tracking et le logging.
    ///
    /// La vraie distribution (burn + reward) se fait via `process_accumulated_fees`
    pub fn transfer_hook(ctx: Context<TransferHook>, amount: u64) -> Result<()> {
        msg!(
            "Transfer Hook: {} tokens from {} to {}",
            amount,
            ctx.accounts.source_token.key(),
            ctx.accounts.destination_token.key()
        );

        // Calculer la fee théorique (0.01%)
        // Note: La vraie fee est gérée par Transfer Fee Extension
        let theoretical_fee = amount
            .checked_mul(TRANSFER_TAX_BPS)
            .unwrap_or(0)
            .checked_div(10_000)
            .unwrap_or(0);

        msg!("Theoretical fee: {} tokens", theoretical_fee);

        Ok(())
    }

    /// Traite les fees accumulées dans le fee vault
    ///
    /// Cette instruction peut être appelée par n'importe qui (permissionless).
    /// Elle distribue les fees collectées:
    /// - 50% sont brûlées (+ CPI record_transfer_burn sur pow-protocol pool 0)
    /// - 50% vont dans pow_reward_vault (+ CPI add_pending_reward splitté 50/50
    ///   entre pool normal et pool seeker)
    ///
    /// Appeler cette instruction périodiquement (pas à chaque transfert)
    /// pour économiser du compute.
    pub fn process_accumulated_fees(ctx: Context<ProcessAccumulatedFees>) -> Result<()> {
        let fee_vault = &ctx.accounts.fee_vault;
        let current_balance = fee_vault.amount;

        if current_balance == 0 {
            msg!("No fees to process");
            return Ok(());
        }

        // Calculer les parts
        let burn_amount = current_balance
            .checked_mul(BURN_PERCENT)
            .ok_or(HookError::Overflow)?
            .checked_div(100)
            .ok_or(HookError::Overflow)?;

        let miner_amount = current_balance
            .checked_sub(burn_amount)
            .ok_or(HookError::Overflow)?;

        msg!("Processing {} tokens from fee vault", current_balance);
        msg!("  Burn: {} tokens (50%)", burn_amount);
        msg!("  Miners: {} tokens (50%)", miner_amount);

        let mint_key = ctx.accounts.mint.key();
        let fee_vault_seeds: &[&[&[u8]]] = &[&[
            FEE_VAULT_SEED,
            mint_key.as_ref(),
            &[ctx.bumps.fee_vault],
        ]];

        // =======================================================================
        // 1. BURN 50%
        // =======================================================================

        if burn_amount > 0 {
            anchor_spl::token_2022::burn(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    anchor_spl::token_2022::Burn {
                        mint: ctx.accounts.mint.to_account_info(),
                        from: ctx.accounts.fee_vault.to_account_info(),
                        authority: ctx.accounts.fee_vault.to_account_info(),
                    },
                    fee_vault_seeds,
                ),
                burn_amount,
            )?;

            msg!("Burned {} tokens", burn_amount);

            // CPI → pow-protocol::record_transfer_burn (split 50/50 normal + seeker)
            let cpi_program = ctx.accounts.pow_program.to_account_info();
            let cpi_accounts = pow_protocol::cpi::accounts::RecordTransferBurn {
                caller: ctx.accounts.fee_vault.to_account_info(),
                pow_config_normal: ctx.accounts.pow_config_normal.to_account_info(),
                pow_config_seeker: ctx.accounts.pow_config_seeker.to_account_info(),
            };
            pow_protocol::cpi::record_transfer_burn(
                CpiContext::new_with_signer(cpi_program, cpi_accounts, fee_vault_seeds),
                burn_amount,
            )?;

            msg!("Recorded burn in pow-protocol (split 50/50 normal + seeker)");
        }

        // =======================================================================
        // 2. TRANSFER 50% vers le Reward Vault du PoW
        // =======================================================================

        if miner_amount > 0 {
            anchor_spl::token_2022::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    anchor_spl::token_2022::TransferChecked {
                        from: ctx.accounts.fee_vault.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.pow_reward_vault.to_account_info(),
                        authority: ctx.accounts.fee_vault.to_account_info(),
                    },
                    fee_vault_seeds,
                ),
                miner_amount,
                ctx.accounts.mint.decimals,
            )?;

            msg!("Transferred {} tokens to miner reward pool", miner_amount);

            // CPI → pow-protocol::add_pending_reward (split 50/50 normal + seeker)
            let cpi_program = ctx.accounts.pow_program.to_account_info();
            let cpi_accounts = pow_protocol::cpi::accounts::AddPendingReward {
                caller: ctx.accounts.fee_vault.to_account_info(),
                pow_config_normal: ctx.accounts.pow_config_normal.to_account_info(),
                pow_config_seeker: ctx.accounts.pow_config_seeker.to_account_info(),
            };
            pow_protocol::cpi::add_pending_reward(
                CpiContext::new_with_signer(cpi_program, cpi_accounts, fee_vault_seeds),
                miner_amount,
            )?;

            msg!("Pending reward updated in pow-protocol (split 50/50 normal + seeker)");
        }

        // =======================================================================
        // 3. Mettre à jour les stats
        // =======================================================================

        let hook_config = &mut ctx.accounts.hook_config;
        hook_config.total_fees_collected = hook_config
            .total_fees_collected
            .checked_add(current_balance)
            .ok_or(HookError::Overflow)?;
        hook_config.total_burned = hook_config
            .total_burned
            .checked_add(burn_amount)
            .ok_or(HookError::Overflow)?;
        hook_config.total_to_miners = hook_config
            .total_to_miners
            .checked_add(miner_amount)
            .ok_or(HookError::Overflow)?;

        msg!("Fee processing complete!");
        msg!("  Total processed historically: {}", hook_config.total_fees_collected);
        msg!("  Total burned historically: {}", hook_config.total_burned);
        msg!("  Total to miners historically: {}", hook_config.total_to_miners);

        Ok(())
    }

    /// Collecte les withheld fees, les retire du mint, puis les distribue
    ///
    /// Permissionless. Fait tout en une seule instruction :
    /// 1. Harvest: collecte les withheld fees des token accounts sources → mint
    /// 2. Withdraw: retire les fees du mint → fee_vault (fee_vault PDA = withdraw authority)
    /// 3. Distribute: burn 50% + transfer 50% → reward vault miners
    ///
    /// remaining_accounts: les token accounts sources à harvest (writable)
    pub fn collect_and_distribute_fees<'info>(
        ctx: Context<'_, '_, '_, 'info, CollectAndDistributeFees<'info>>,
    ) -> Result<()> {
        let mint_key = ctx.accounts.mint.key();
        let fee_vault_seeds: &[&[&[u8]]] = &[&[
            FEE_VAULT_SEED,
            mint_key.as_ref(),
            &[ctx.bumps.fee_vault],
        ]];

        // =====================================================================
        // 1. HARVEST: withheld fees from source accounts → mint
        // =====================================================================
        let sources = ctx.remaining_accounts;
        if !sources.is_empty() {
            // Build HarvestWithheldTokensToMint instruction
            // TokenInstruction::TransferFeeExtension = 26, sub = 4
            let data = vec![26u8, 4u8];

            let mut account_metas = vec![
                AccountMeta::new(ctx.accounts.mint.key(), false),
            ];
            for source in sources.iter() {
                account_metas.push(AccountMeta::new(source.key(), false));
            }

            let ix = Instruction {
                program_id: ctx.accounts.token_program.key(),
                accounts: account_metas,
                data,
            };

            let mut account_infos = vec![ctx.accounts.mint.to_account_info()];
            for source in sources.iter() {
                account_infos.push(source.clone());
            }

            // Permissionless — no signer needed
            invoke_signed(&ix, &account_infos, &[])?;

            msg!("Harvested withheld fees from {} accounts", sources.len());
        }

        // =====================================================================
        // 2. WITHDRAW: from mint → fee_vault (fee_vault PDA = withdraw authority)
        // =====================================================================
        // WithdrawWithheldTokensFromMint: instruction=26, sub=2
        // Accounts: [mint (writable), destination (writable), authority (signer)]
        {
            let data = vec![26u8, 2u8];

            let account_metas = vec![
                AccountMeta::new(ctx.accounts.mint.key(), false),
                AccountMeta::new(ctx.accounts.fee_vault.key(), false),
                AccountMeta::new_readonly(ctx.accounts.fee_vault.key(), true), // authority = fee_vault PDA
            ];

            let ix = Instruction {
                program_id: ctx.accounts.token_program.key(),
                accounts: account_metas,
                data,
            };

            let account_infos = vec![
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.fee_vault.to_account_info(),
                ctx.accounts.fee_vault.to_account_info(),
            ];

            invoke_signed(&ix, &account_infos, fee_vault_seeds)?;

            msg!("Withdrew withheld fees from mint to fee_vault");
        }

        // =====================================================================
        // 3. DISTRIBUTE: burn 100% from fee_vault
        //    - record_transfer_burn for 50% (permanent deflation)
        //    - add_pending_reward for 50% (will be minted fresh to next miner)
        // =====================================================================
        // Note: We burn ALL tokens and use add_pending_reward to re-mint the
        // miner share. We can't use transfer_checked here because Token-2022
        // would re-enter this hook program (reentrancy not allowed on Solana).
        ctx.accounts.fee_vault.reload()?;
        let current_balance = ctx.accounts.fee_vault.amount;

        if current_balance == 0 {
            msg!("No fees to distribute");
            return Ok(());
        }

        // Calculate cranker reward (0.01% of total fees)
        let cranker_reward = current_balance
            .checked_mul(CRANKER_REWARD_BPS)
            .ok_or(HookError::Overflow)?
            .checked_div(BPS_DENOMINATOR)
            .ok_or(HookError::Overflow)?;

        // Remaining after cranker cut
        let distributable = current_balance
            .checked_sub(cranker_reward)
            .ok_or(HookError::Overflow)?;

        let burn_share = distributable
            .checked_mul(BURN_PERCENT)
            .ok_or(HookError::Overflow)?
            .checked_div(100)
            .ok_or(HookError::Overflow)?;

        let miner_share = distributable
            .checked_sub(burn_share)
            .ok_or(HookError::Overflow)?;

        msg!("Distributing {} tokens: cranker={}, burn={}, miners={}",
            current_balance, cranker_reward, burn_share, miner_share);

        // Burn 100% of fee_vault balance (cranker reward will be minted fresh)
        anchor_spl::token_2022::burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token_2022::Burn {
                    mint: ctx.accounts.mint.to_account_info(),
                    from: ctx.accounts.fee_vault.to_account_info(),
                    authority: ctx.accounts.fee_vault.to_account_info(),
                },
                fee_vault_seeds,
            ),
            current_balance,
        )?;

        // Record the burn share (50% of distributable) as permanent deflation
        // Also record the cranker reward as burn since it will be re-minted
        // Net effect: burn_share reduces supply permanently, cranker_reward is neutral
        if burn_share > 0 {
            let cpi_program = ctx.accounts.pow_program.to_account_info();
            let cpi_accounts = pow_protocol::cpi::accounts::RecordTransferBurn {
                caller: ctx.accounts.fee_vault.to_account_info(),
                pow_config_normal: ctx.accounts.pow_config_normal.to_account_info(),
                pow_config_seeker: ctx.accounts.pow_config_seeker.to_account_info(),
            };
            pow_protocol::cpi::record_transfer_burn(
                CpiContext::new_with_signer(cpi_program, cpi_accounts, fee_vault_seeds),
                burn_share,
            )?;
        }

        // Record the miner share (50% of distributable) as pending reward — will be minted fresh
        if miner_share > 0 {
            let cpi_program = ctx.accounts.pow_program.to_account_info();
            let cpi_accounts = pow_protocol::cpi::accounts::AddPendingReward {
                caller: ctx.accounts.fee_vault.to_account_info(),
                pow_config_normal: ctx.accounts.pow_config_normal.to_account_info(),
                pow_config_seeker: ctx.accounts.pow_config_seeker.to_account_info(),
            };
            pow_protocol::cpi::add_pending_reward(
                CpiContext::new_with_signer(cpi_program, cpi_accounts, fee_vault_seeds),
                miner_share,
            )?;
        }

        // Mint cranker reward directly to cranker's token account
        if cranker_reward > 0 {
            let cpi_program = ctx.accounts.pow_program.to_account_info();
            let cpi_accounts = pow_protocol::cpi::accounts::MintCrankerReward {
                caller: ctx.accounts.fee_vault.to_account_info(),
                pow_config_normal: ctx.accounts.pow_config_normal.to_account_info(),
                pow_config_seeker: ctx.accounts.pow_config_seeker.to_account_info(),
                mint_authority: ctx.accounts.mint_authority.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                cranker_token_account: ctx.accounts.cranker_token_account.to_account_info(),
                token_program: ctx.accounts.token_program.to_account_info(),
            };
            pow_protocol::cpi::mint_cranker_reward(
                CpiContext::new_with_signer(cpi_program, cpi_accounts, fee_vault_seeds),
                cranker_reward,
            )?;
        }

        // Update stats
        let hook_config = &mut ctx.accounts.hook_config;
        hook_config.total_fees_collected = hook_config
            .total_fees_collected
            .checked_add(current_balance)
            .ok_or(HookError::Overflow)?;
        hook_config.total_burned = hook_config
            .total_burned
            .checked_add(burn_share)
            .ok_or(HookError::Overflow)?;
        hook_config.total_to_miners = hook_config
            .total_to_miners
            .checked_add(miner_share)
            .ok_or(HookError::Overflow)?;

        msg!("Fee collection complete!");
        msg!("  Cranker reward: {}", cranker_reward);
        msg!("  Burned: {}", burn_share);
        msg!("  To miners: {}", miner_share);
        msg!("  Total processed historically: {}", hook_config.total_fees_collected);

        Ok(())
    }

    /// Crée le fee vault (token account PDA)
    ///
    /// Appelé une fois après l'initialisation du mint
    pub fn create_fee_vault(ctx: Context<CreateFeeVault>) -> Result<()> {
        msg!("Fee vault created: {}", ctx.accounts.fee_vault.key());
        Ok(())
    }

    /// Fallback pour l'interface SPL Transfer Hook
    ///
    /// SPL Token-2022 appelle cette fonction avec un discriminateur personnalisé
    pub fn fallback<'info>(
        program_id: &Pubkey,
        accounts: &'info [AccountInfo<'info>],
        data: &[u8],
    ) -> Result<()> {
        let instruction = TransferHookInstruction::unpack(data)?;

        match instruction {
            TransferHookInstruction::Execute { amount } => {
                let amount_bytes = amount.to_le_bytes();
                __private::__global::transfer_hook(program_id, accounts, &amount_bytes)
            }
            _ => {
                msg!("Fallback: Unknown instruction");
                Err(ProgramError::InvalidInstructionData.into())
            }
        }
    }
}

// =============================================================================
// STRUCTURES DE DONNÉES
// =============================================================================

/// Configuration du Transfer Hook
#[account]
#[derive(Default)]
pub struct HookConfig {
    /// Mint du token
    pub mint: Pubkey,

    /// Program ID du PoW protocol
    pub pow_program_id: Pubkey,

    /// Total des fees collectées (historique)
    pub total_fees_collected: u64,

    /// Total des tokens brûlés (historique)
    pub total_burned: u64,

    /// Total des tokens envoyés aux mineurs (historique)
    pub total_to_miners: u64,

    /// Bump du PDA
    pub bump: u8,
}

impl HookConfig {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // mint
        32 +    // pow_program_id
        8 +     // total_fees_collected
        8 +     // total_burned
        8 +     // total_to_miners
        1;      // bump
}

// =============================================================================
// CONTEXTES
// =============================================================================

#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    /// Payeur pour la création des comptes
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Le mint du token SPL2022
    #[account(
        mint::token_program = token_program,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// PDA pour stocker les extra account metas
    /// CHECK: Initialisé dans l'instruction
    #[account(
        mut,
        seeds = [EXTRA_ACCOUNT_METAS_SEED, mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,

    /// Configuration du hook
    #[account(
        init,
        payer = payer,
        space = HookConfig::LEN,
        seeds = [b"hook_config", mint.key().as_ref()],
        bump,
    )]
    pub hook_config: Account<'info, HookConfig>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateFeeVault<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mint::token_program = token_program,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Fee vault - PDA token account
    #[account(
        init,
        payer = payer,
        seeds = [FEE_VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = fee_vault, // Self-authority (PDA)
        token::token_program = token_program,
    )]
    pub fee_vault: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

/// Contexte pour le transfer hook (appelé par SPL Token-2022)
///
/// NOTE: Le hook reçoit exactement 5 comptes standard + les extra accounts.
/// Anchor parse les 5 premiers champs du struct dans l'ordre, puis les extras
/// sont accessibles via remaining_accounts si nécessaire.
/// On NE met PAS token_program ici car ça décalerait le parsing vers les extra accounts.
#[derive(Accounts)]
pub struct TransferHook<'info> {
    /// Source token account
    #[account(
        token::mint = mint,
    )]
    pub source_token: InterfaceAccount<'info, TokenAccount>,

    /// Mint du token
    pub mint: InterfaceAccount<'info, Mint>,

    /// Destination token account
    #[account(
        token::mint = mint,
    )]
    pub destination_token: InterfaceAccount<'info, TokenAccount>,

    /// Owner de la source
    /// CHECK: Validé par le token program
    pub source_authority: UncheckedAccount<'info>,

    /// Extra account meta list (requis par l'interface)
    /// CHECK: Validé par les seeds
    #[account(
        seeds = [EXTRA_ACCOUNT_METAS_SEED, mint.key().as_ref()],
        bump,
    )]
    pub extra_account_meta_list: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct ProcessAccumulatedFees<'info> {
    /// N'importe qui peut appeler cette instruction
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Le mint du token
    #[account(mut)]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Fee vault contenant les fees accumulées
    #[account(
        mut,
        seeds = [FEE_VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = fee_vault,
        token::token_program = token_program,
    )]
    pub fee_vault: InterfaceAccount<'info, TokenAccount>,

    /// Vault du programme PoW pour les rewards mineurs
    #[account(
        mut,
        token::mint = mint,
        token::token_program = token_program,
    )]
    pub pow_reward_vault: InterfaceAccount<'info, TokenAccount>,

    /// Configuration du hook
    #[account(
        mut,
        seeds = [b"hook_config", mint.key().as_ref()],
        bump = hook_config.bump,
    )]
    pub hook_config: Account<'info, HookConfig>,

    /// PoW Config normal (pool 0) - pour record_transfer_burn + add_pending_reward
    /// CHECK: PDA du programme pow-protocol, validé par le CPI
    #[account(mut)]
    pub pow_config_normal: AccountInfo<'info>,

    /// PoW Config seeker (pool 1) - pour add_pending_reward
    /// CHECK: PDA du programme pow-protocol, validé par le CPI
    #[account(mut)]
    pub pow_config_seeker: AccountInfo<'info>,

    /// Programme pow-protocol (pour CPI)
    /// CHECK: Validé par contrainte
    #[account(
        constraint = pow_program.key() == hook_config.pow_program_id @ HookError::InvalidPowProgram,
    )]
    pub pow_program: AccountInfo<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

/// Contexte pour collect_and_distribute_fees
/// Combine harvest + withdraw + distribute en une seule instruction
/// remaining_accounts: token accounts sources à harvest (writable)
#[derive(Accounts)]
pub struct CollectAndDistributeFees<'info> {
    /// N'importe qui peut appeler (permissionless)
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Le mint du token (withheld fees sont stockées ici après harvest)
    #[account(mut)]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Fee vault — PDA qui est aussi le withdraw authority du mint
    #[account(
        mut,
        seeds = [FEE_VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = fee_vault,
        token::token_program = token_program,
    )]
    pub fee_vault: InterfaceAccount<'info, TokenAccount>,

    /// Configuration du hook
    #[account(
        mut,
        seeds = [b"hook_config", mint.key().as_ref()],
        bump = hook_config.bump,
    )]
    pub hook_config: Account<'info, HookConfig>,

    /// PoW Config normal (pool 0)
    /// CHECK: PDA du programme pow-protocol, validé par le CPI
    #[account(mut)]
    pub pow_config_normal: AccountInfo<'info>,

    /// PoW Config seeker (pool 1)
    /// CHECK: PDA du programme pow-protocol, validé par le CPI
    #[account(mut)]
    pub pow_config_seeker: AccountInfo<'info>,

    /// Programme pow-protocol (pour CPI)
    /// CHECK: Validé par contrainte
    #[account(
        constraint = pow_program.key() == hook_config.pow_program_id @ HookError::InvalidPowProgram,
    )]
    pub pow_program: AccountInfo<'info>,

    /// Mint authority PDA de pow-protocol (pour mint_cranker_reward CPI)
    /// CHECK: PDA de pow-protocol, validé par le CPI
    pub mint_authority: AccountInfo<'info>,

    /// Token account du cranker (reçoit la reward mintée)
    /// CHECK: Validé par le CPI mint_cranker_reward
    #[account(mut)]
    pub cranker_token_account: AccountInfo<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

// =============================================================================
// ERREURS
// =============================================================================

#[error_code]
pub enum HookError {
    #[msg("Arithmetic overflow")]
    Overflow,

    #[msg("Invalid mint")]
    InvalidMint,

    #[msg("Unauthorized")]
    Unauthorized,

    #[msg("Invalid PoW program ID")]
    InvalidPowProgram,
}
