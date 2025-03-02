# -*- coding: utf-8 -*-
"""
@author: iceland
"""
import sys
import argparse
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

try:
import secp256k1 as ice
except ImportError:
print("[ERROR] The 'secp256k1' library is not installed.")
sys.exit(1)

# ============================================================================
parser = argparse.ArgumentParser(description="This script gets r, s, and z values ​​of ECDSA signatures from a Bitcoin transaction.",
epilog="Enjoy! :) BTC Tips: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at")

parser.add_argument("-txid", help="txid of the transaction. Automatically gets the rawtx from the blockchain.", action="store")
parser.add_argument("-rawtx", help="Raw transaction on the blockchain.", action="store")

if len(sys.argv) == 1:
 parser.print_help()
 sys.exit(1)

args = parser.parse_args()
# ============================================================================

txid = args.txid if args.txid else ''
rawtx = args.rawtx if args.rawtx else ''

if not rawtx and not txid:
print("[ERROR] You must provide either -rawtx or -txid.")
sys.exit(1)

# ================================================================================

def get_rs(sig):
try:
rlen = int(sig[2:4], 16)
r = sig[4:4 + rlen * 2]
s = sig[8 + rlen * 2:]
return r, s
except (ValueError, IndexError):
print("[ERROR] Failed to process signature.")
sys.exit(1)

def split_sig_pieces(script):
try:
sigLen = int(script[2:4], 16)
sig = script[2 + 2:2 + sigLen * 2]
r, s = get_rs(sig[4:])
pubLen = int(script[4 + sigLen * 2:4 + sigLen * 2 + 2], 16)
pub = script[4 + sigLen * 2 + 2:]

if len(pub) != pubLen * 2:
raise ValueError("Invalid public key length.")

return r, s, pub
except (ValueError, IndexError):
print("[ERROR] Failed to split signature.")
sys.exit(1)

def parseTx(txn):
if len(txn) < 130:
print("[ERROR] Invalid rawtx. Check the data.")
sys.exit(1)

inp_list = []
ver = txn[:8]

if txn[8:12] == '0001':
print("[ERROR] Unsupported Witness (SegWit) transaction.")
sys.exit(1)

try:
inp_nu = int(txn[8:10], 16)
except ValueError:
print("[ERROR] Failed to process number of inputs.")
sys.exit(1)
first = txn[0:10]
cur = 10
for _ in range(inp_nu):
try:
prv_out = txn[cur:cur + 64]
var0 = txn[cur + 64:cur + 64 + 8]
cur += 64 + 8 scriptLen = int(txn[cur:cur + 2], 16)
 script = txn[cur:2 + cur + 2 * scriptLen]
 r, s, pub = split_sig_pieces(script)
 seq = txn[2 + cur + 2 * scriptLen:10 + cur + 2 * scriptLen]
 inp_list.append([prv_out, var0, r, s, pub, seq])
 cur = 10 + cur + 2 * scriptLen
 except (ValueError, IndexError):
 print("[ERROR] Failed to process transaction input.")
 sys.exit(1)
   rest = txn[cur:]
 return [first, inp_list, rest]

def get_rawtx_from_blockchain(txid):
 try:
 url = f"https://blockchain.info/rawtx/{txid}?format=hex"
 response = urlopen(url, timeout=20)
 return response.read().decode('utf-8')
 except HTTPError as e:
 print(f"[ERROR] HTTP Error {e.code}: {e.reason}")
 except URLError as e:
 print(f"[ERROR] Connection failure: {e.reason}")
 except Exception as e:
 print(f"[ERROR] Unexpected error: {str(e)}")
 sys.exit(1)

def HASH160(pubk_hex):
 try:
 iscompressed = len(pubk_hex) < 70
 P = ice.pub2upub(pubk_hex)
 return ice.pubkey_to_h160(0, iscompressed, P).hex()
 exceptException:
 print("[ERROR] Failed to calculate HASH160.")
 sys.exit(1)

def getSignableTxn(parsed):
 res = []
 first, inp_list, rest = parsed
 tot = len(inp_list)

 for one in range(tot):
 e = first
 for i in range(tot):
 and += inp_list[i][0] # prev_txid
 and += inp_list[i][1] # var0
 if one == i:
 and += '1976a914' + HASH160(inp_list[one][4]) + '88ac'
 else:
 and += '00'
 and += inp_list[i][5] # seq

 and += rest + "01000000"

 try:
 z = ice.get_sha256(ice.get_sha256(bytes.fromhex(e))).hex()
 exceptException:
 print("[ERROR] Failed to calculate transaction hash.")
 sys.exit(1)

 res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])

 return res

# ============================================================================

if rawtx == '':
 rawtx = get_rawtx_from_blockchain(txid)

print("\nStarting program...")

try:
 m = parseTx(rawtx)
 e = getSignableTxn(m)

 for i in range(len(e)):
 print("=" * 70, f"\n[Input Index #: {i}]\n R: {e[i][0]}\n S: {e[i][1]}\n Z: {e[i][2]}\nPubKey: {e[i][3]}")
except Exception as err:
 print(f"[ERROR] Unexpected failure: {err}")
 sys.exit(1)