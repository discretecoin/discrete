/* Experimental isolated-VM profile: fixed program id, fixed test mint, SPL Token only.
 * No admin, upgrade, close, reinitialize, pooled vault or arbitrary destination path.
 * Production USDC deployment and issuer/finality assumptions are separate qualification gates. */
#include <solana_sdk.h>
#include "solana_profile.h"

#define ERR(x) (0x1000u+(x))
enum { STATE, VAULT, MINT, CLAIM, REFUND, SOURCE, DEPOSITOR, AUTHORITY, TOKEN, CLOCK, COUNT };
static uint64_t read64(const uint8_t *p) {uint64_t v=0;for(int i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void write64(uint8_t *p,uint64_t v) {for(int i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i));}
static bool same(const uint8_t *a,const uint8_t *b,uint64_t n) {for(uint64_t i=0;i<n;i++)if(a[i]!=b[i])return false;return true;}
static bool zero(const uint8_t *a,uint64_t n) {for(uint64_t i=0;i<n;i++)if(a[i])return false;return true;}
static void copy(uint8_t *a,const uint8_t *b,uint64_t n) {for(uint64_t i=0;i<n;i++)a[i]=b[i];}
static bool key(const SolPubkey *a,const uint8_t *b) {return same(a->x,b,32);}
static bool token_account(const SolAccountInfo *a,const SolPubkey *mint) {
  return key(a->owner,TOKEN_ID) && !a->executable && a->data_len==165 &&
    same(a->data,mint->x,32) && a->data[108]==1 && zero(a->data+109,4);
}
static uint64_t transfer(SolParameters *p,int source,int dest,uint64_t amount,
                         const SolSignerSeeds *seeds,int nseeds) {
  SolAccountInfo *a=p->ka;int auth=nseeds?AUTHORITY:DEPOSITOR;
  if(read64(a[dest].data+64)>UINT64_MAX-amount)return ERR(18);
  uint8_t data[10]={12};write64(data+1,amount);data[9]=6; /* SPL TransferChecked */
  SolAccountMeta metas[4]={{a[source].key,true,false},{a[MINT].key,false,false},
                         {a[dest].key,true,false},{a[auth].key,false,true}};
  SolInstruction ix={a[TOKEN].key,metas,4,data,sizeof(data)};
  return sol_invoke_signed(&ix,a,COUNT,seeds,nseeds);
}

uint64_t entrypoint(const uint8_t *input) {
  SolAccountInfo accounts[COUNT];SolParameters p={.ka=accounts};
  /* Runtime supplies the serialized account buffer. Bound account count before SDK traversal. */
  if(read64(input)!=COUNT || !sol_deserialize(input,&p,COUNT))return ERR(1);
  SolAccountInfo *a=p.ka;
  if(!key(p.program_id,PROGRAM_ID) || p.data_len<1)return ERR(2);
  for(int i=0;i<COUNT;i++)for(int j=0;j<i;j++)if(SolPubkey_same(a[i].key,a[j].key))return ERR(3);
  if(!SolPubkey_same(a[STATE].owner,p.program_id) || a[STATE].data_len!=192 ||
     !a[STATE].is_writable || !a[VAULT].is_writable || a[STATE].executable)return ERR(4);
  if(!key(a[TOKEN].key,TOKEN_ID) || !a[TOKEN].executable || !key(a[MINT].key,MINT_ID) ||
     !key(a[MINT].owner,TOKEN_ID) || a[MINT].data_len!=82 || a[MINT].data[44]!=6 || a[MINT].data[45]!=1)return ERR(5);
  if(!key(a[CLOCK].key,CLOCK_ID) || !key(a[CLOCK].owner,SYSVAR_ID) || a[CLOCK].data_len!=40)return ERR(6);
  uint64_t slot=read64(a[CLOCK].data);uint8_t *s=a[STATE].data;
  SolSignerSeed base[2]={{(const uint8_t *)"xds-swap-v1",11},{a[STATE].key->x,32}};
  SolPubkey authority;uint8_t bump=0;
  if(sol_try_find_program_address(base,2,p.program_id,&authority,&bump)!=SUCCESS ||
     !SolPubkey_same(&authority,a[AUTHORITY].key))return ERR(7);
  if(!token_account(&a[VAULT],a[MINT].key) || !same(a[VAULT].data+32,authority.x,32) ||
     !zero(a[VAULT].data+72,4) || !zero(a[VAULT].data+129,4))return ERR(8);
  uint8_t op=p.data[0];
  if(op==0) {
    if(p.data_len!=49 || !zero(s,192) || !a[STATE].is_signer || !a[DEPOSITOR].is_signer ||
       !a[SOURCE].is_writable || !token_account(&a[SOURCE],a[MINT].key) ||
       !same(a[SOURCE].data+32,a[DEPOSITOR].key->x,32) || !zero(a[SOURCE].data+72,4) ||
       !token_account(&a[CLAIM],a[MINT].key) || !token_account(&a[REFUND],a[MINT].key))return ERR(9);
    uint64_t amount=read64(p.data+1),deadline=read64(p.data+9);
    if(!amount || deadline<=slot || read64(a[VAULT].data+64)!=0 || read64(a[SOURCE].data+64)<amount)return ERR(10);
    uint64_t result=transfer(&p,SOURCE,VAULT,amount,0,0);if(result)return result;
    copy(s,(const uint8_t *)"XDSV0001",8);s[8]=1;s[9]=bump;
    write64(s+16,amount);write64(s+24,deadline);copy(s+32,p.data+17,32);
    copy(s+64,a[VAULT].key->x,32);copy(s+96,a[MINT].key->x,32);
    copy(s+128,a[CLAIM].key->x,32);copy(s+160,a[REFUND].key->x,32);
    return SUCCESS;
  }
  if(op!=1 && op!=2)return ERR(11);
  if(!same(s,(const uint8_t *)"XDSV0001",8) || s[8]!=1 || s[9]!=bump || !zero(s+10,6) ||
     !key(a[VAULT].key,s+64) || !key(a[MINT].key,s+96) ||
     !key(a[CLAIM].key,s+128) || !key(a[REFUND].key,s+160))return ERR(12);
  if(op==1) {
    if(p.data_len!=33)return ERR(13);
    uint8_t h[32];SolBytes secret={p.data+1,32};
    if(sol_sha256(&secret,1,h)!=SUCCESS || !same(h,s+32,32))return ERR(14);
  } else if(p.data_len!=1 || slot<read64(s+24))return ERR(15);
  int dest=op==1?CLAIM:REFUND;
  if(!a[dest].is_writable || !token_account(&a[dest],a[MINT].key))return ERR(16);
  uint64_t amount=read64(s+16);if(!amount || read64(a[VAULT].data+64)<amount)return ERR(17);
  SolSignerSeed seeds[3]={base[0],base[1],{&bump,1}};SolSignerSeeds signer={seeds,3};
  uint64_t result=transfer(&p,VAULT,dest,amount,&signer,1);if(result)return result;
  s[8]=op==1?2:3; /* Terminal tombstone remains, even when vault is empty. */
  return SUCCESS;
}
