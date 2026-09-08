"""Experimental native Bitcoin P2WSH adapter. No keys or RPC credentials persisted here."""
import hashlib
import struct
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
sha = lambda b: hashlib.sha256(b).digest()
dsha = lambda b: sha(sha(b))
u32 = lambda n: struct.pack('<I', n)
u64 = lambda n: struct.pack('<Q', n)

def compact(n):
    if n < 253: return bytes([n])
    if n <= 65535: return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + u32(n)

def push(b):
    if len(b) > 75: raise ValueError('only minimal short pushes')
    return bytes([len(b)]) + b

def scriptnum(n):
    if not 17 <= n < 500_000_000: raise ValueError('height only, >=17')
    b = n.to_bytes((n.bit_length()+7)//8, 'little')
    return b + (b'\0' if b[-1]&128 else b'')

def pubkey(sk):
    return sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)

@dataclass(frozen=True)
class Contract:
    hashlock: bytes
    claim_pub: bytes
    refund_pub: bytes
    refund_height: int

    def script(self):
        if len(self.hashlock)!=32 or any(len(p)!=33 or p[0] not in (2,3) for p in (self.claim_pub,self.refund_pub)):
            raise ValueError('noncanonical contract')
        # IF SIZE 32 EQUALVERIFY SHA256 H EQUALVERIFY A CHECKSIG ELSE Ht CLTV DROP B CHECKSIG ENDIF
        return b'\x63\x82'+push(b'\x20')+b'\x88\xa8'+push(self.hashlock)+b'\x88'+push(self.claim_pub)+b'\xac\x67'+push(scriptnum(self.refund_height))+b'\xb1\x75'+push(self.refund_pub)+b'\xac\x68'

def spend(contract, txid, vout, amount, destination_script, key, secret=None, fee=1000,
          sequence=0xfffffffe, locktime=None):
    """Sign full input/output state with SIGHASH_ALL. Amount and fee are integer satoshis."""
    if not 0 <= vout < 2**32 or not 0 < fee < amount <= 21_000_000*100_000_000:
        raise ValueError('amount/outpoint')
    if not destination_script or len(destination_script)>10_000: raise ValueError('destination')
    claim = secret is not None
    if claim and (len(secret)!=32 or sha(secret)!=contract.hashlock): raise ValueError('secret')
    if pubkey(key)!=(contract.claim_pub if claim else contract.refund_pub): raise ValueError('role key')
    script=contract.script()
    locktime = (0 if claim else contract.refund_height) if locktime is None else locktime
    prevout=bytes.fromhex(txid)[::-1]+u32(vout)
    output=u64(amount-fee)+compact(len(destination_script))+destination_script
    digest=dsha(u32(2)+dsha(prevout)+dsha(u32(sequence))+prevout+compact(len(script))+script+
                 u64(amount)+u32(sequence)+dsha(output)+u32(locktime)+u32(1))
    sig=key.sign(digest,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r,s=utils.decode_dss_signature(sig); sig=utils.encode_dss_signature(r,min(s,N-s))+b'\x01'
    stack=[sig,secret,b'\x01',script] if claim else [sig,b'',script]
    vin=compact(1)+prevout+b'\0'+u32(sequence)
    vout_bytes=compact(1)+output
    raw=u32(2)+b'\0\x01'+vin+vout_bytes+compact(len(stack))+b''.join(compact(len(x))+x for x in stack)+u32(locktime)
    txid=dsha(u32(2)+vin+vout_bytes+u32(locktime))[::-1].hex()
    return raw.hex(),txid
