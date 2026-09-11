//! Fixed-profile escrow. The build wrapper binds program identity and one mint immutably.
use solana_program::{
    account_info::AccountInfo,
    entrypoint::{deserialize, ProgramResult},
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
};

const STATE: usize = 0;
const VAULT: usize = 1;
const MINT: usize = 2;
const CLAIM: usize = 3;
const REFUND: usize = 4;
const SOURCE: usize = 5;
const DEPOSITOR: usize = 6;
const AUTHORITY: usize = 7;
const TOKEN: usize = 8;
const CLOCK: usize = 9;
const COUNT: usize = 10;
include!("profile.rs");
const TOKEN_ID: [u8; 32] = [6,221,246,225,215,101,161,147,217,203,225,70,206,235,121,172,28,180,133,237,95,91,55,145,58,140,245,133,126,255,0,169];
const CLOCK_ID: [u8; 32] = [6,167,213,23,24,199,116,201,40,86,99,152,105,29,94,182,139,94,184,163,155,75,109,92,115,85,91,33,0,0,0,0];
const SYSVAR_ID: [u8; 32] = [6,167,213,23,24,117,247,41,199,61,147,64,143,33,97,32,6,126,216,140,118,224,140,40,127,193,148,96,0,0,0,0];

fn err(n: u32) -> ProgramError { ProgramError::Custom(0x1000 + n) }
fn zero(data: &[u8]) -> bool { data.iter().all(|v| *v == 0) }
fn read64(data: &[u8]) -> u64 {
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&data[..8]);
    u64::from_le_bytes(bytes)
}
fn key(key: &Pubkey, bytes: &[u8]) -> bool { key.as_ref() == bytes }
fn token_account(account: &AccountInfo, mint: &Pubkey) -> Result<bool, ProgramError> {
    if !key(account.owner, &TOKEN_ID) || account.executable || account.data_len() != 165 { return Ok(false); }
    let data = account.try_borrow_data()?;
    Ok(&data[..32] == mint.as_ref() && data[108] == 1 && zero(&data[109..113]))
}
fn token_amount(account: &AccountInfo) -> Result<u64, ProgramError> {
    Ok(read64(&account.try_borrow_data()?[64..72]))
}

// Preserve C's exact count gate before invoking the supported SDK deserializer.
// Safety: only the Solana runtime calls this ABI with its serialized account buffer.
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    let count = unsafe { u64::from_le(std::ptr::read_unaligned(input.cast::<u64>())) };
    if count != COUNT as u64 { return err(1).into(); }
    let (program_id, accounts, data) = unsafe { deserialize(input) };
    match process_instruction(program_id, &accounts, data) {
        Ok(()) => 0,
        Err(error) => error.into(),
    }
}
solana_program::custom_heap_default!();
solana_program::custom_panic_default!();

fn transfer(a: &[AccountInfo], source: usize, dest: usize, amount: u64, seeds: &[&[&[u8]]]) -> ProgramResult {
    let auth = if seeds.is_empty() { DEPOSITOR } else { AUTHORITY };
    if token_amount(&a[dest])? > u64::MAX - amount { return Err(err(18)); }
    let mut data = vec![12];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(6);
    let instruction = Instruction {
        program_id: *a[TOKEN].key,
        accounts: vec![AccountMeta::new(*a[source].key, false), AccountMeta::new_readonly(*a[MINT].key, false),
                       AccountMeta::new(*a[dest].key, false), AccountMeta::new_readonly(*a[auth].key, true)],
        data,
    };
    // All validation data borrows ended before this standard checked CPI path.
    invoke_signed(&instruction, a, seeds)
}

pub fn process_instruction(program_id: &Pubkey, a: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if a.len() != COUNT { return Err(err(1)); }
    if !key(program_id, &PROGRAM_ID) || data.is_empty() { return Err(err(2)); }
    for i in 0..COUNT {
        for j in 0..i { if a[i].key == a[j].key { return Err(err(3)); } }
    }
    if a[STATE].owner != program_id || a[STATE].data_len() != 192 || !a[STATE].is_writable
        || !a[VAULT].is_writable || a[STATE].executable { return Err(err(4)); }
    if !key(a[TOKEN].key, &TOKEN_ID) || !a[TOKEN].executable || !key(a[MINT].key, &MINT_ID)
        || !key(a[MINT].owner, &TOKEN_ID) || a[MINT].data_len() != 82 { return Err(err(5)); }
    {
        let mint = a[MINT].try_borrow_data()?;
        if mint[44] != 6 || mint[45] != 1 { return Err(err(5)); }
    }
    if !key(a[CLOCK].key, &CLOCK_ID) || !key(a[CLOCK].owner, &SYSVAR_ID) || a[CLOCK].data_len() != 40 { return Err(err(6)); }
    let slot = read64(&a[CLOCK].try_borrow_data()?);
    let base: [&[u8]; 2] = [b"xds-swap-v1", a[STATE].key.as_ref()];
    let (authority, bump) = Pubkey::try_find_program_address(&base, program_id).ok_or_else(|| err(7))?;
    if &authority != a[AUTHORITY].key { return Err(err(7)); }
    if !token_account(&a[VAULT], a[MINT].key)? { return Err(err(8)); }
    {
        let vault = a[VAULT].try_borrow_data()?;
        if &vault[32..64] != authority.as_ref() || !zero(&vault[72..76]) || !zero(&vault[129..133]) { return Err(err(8)); }
    }
    // Copy the immutable state for validation; no Ref/RefMut may survive token CPI.
    let mut state = [0; 192];
    state.copy_from_slice(&a[STATE].try_borrow_data()?);
    let op = data[0];
    if op == 0 {
        if data.len() != 49 || !zero(&state) || !a[STATE].is_signer || !a[DEPOSITOR].is_signer
            || !a[SOURCE].is_writable || !token_account(&a[SOURCE], a[MINT].key)? { return Err(err(9)); }
        {
            let source = a[SOURCE].try_borrow_data()?;
            if &source[32..64] != a[DEPOSITOR].key.as_ref() || !zero(&source[72..76]) { return Err(err(9)); }
        }
        if !token_account(&a[CLAIM], a[MINT].key)? || !token_account(&a[REFUND], a[MINT].key)? { return Err(err(9)); }
        let amount = read64(&data[1..9]);
        let deadline = read64(&data[9..17]);
        if amount == 0 || deadline <= slot || token_amount(&a[VAULT])? != 0 || token_amount(&a[SOURCE])? < amount { return Err(err(10)); }
        transfer(a, SOURCE, VAULT, amount, &[])?;
        let mut out = a[STATE].try_borrow_mut_data()?;
        out[..8].copy_from_slice(b"XDSV0001"); out[8] = 1; out[9] = bump;
        out[16..24].copy_from_slice(&amount.to_le_bytes()); out[24..32].copy_from_slice(&deadline.to_le_bytes());
        out[32..64].copy_from_slice(&data[17..49]);
        out[64..96].copy_from_slice(a[VAULT].key.as_ref()); out[96..128].copy_from_slice(a[MINT].key.as_ref());
        out[128..160].copy_from_slice(a[CLAIM].key.as_ref()); out[160..192].copy_from_slice(a[REFUND].key.as_ref());
        return Ok(());
    }
    if op != 1 && op != 2 { return Err(err(11)); }
    if &state[..8] != b"XDSV0001" || state[8] != 1 || state[9] != bump || !zero(&state[10..16])
        || !key(a[VAULT].key, &state[64..96]) || !key(a[MINT].key, &state[96..128])
        || !key(a[CLAIM].key, &state[128..160]) || !key(a[REFUND].key, &state[160..192]) { return Err(err(12)); }
    if op == 1 {
        if data.len() != 33 { return Err(err(13)); }
        if hashv(&[&data[1..33]]).as_ref() != &state[32..64] { return Err(err(14)); }
    } else if data.len() != 1 || slot < read64(&state[24..32]) { return Err(err(15)); }
    let dest = if op == 1 { CLAIM } else { REFUND };
    if !a[dest].is_writable || !token_account(&a[dest], a[MINT].key)? { return Err(err(16)); }
    let amount = read64(&state[16..24]);
    if amount == 0 || token_amount(&a[VAULT])? < amount { return Err(err(17)); }
    let bump_seed = [bump];
    let signer: [&[u8]; 3] = [base[0], base[1], &bump_seed];
    transfer(a, VAULT, dest, amount, &[&signer])?;
    a[STATE].try_borrow_mut_data()?[8] = if op == 1 { 2 } else { 3 };
    Ok(())
}
