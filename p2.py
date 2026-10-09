import hashlib
import secrets

from embit.ec import ECError, PrivateKey
from embit.networks import NETWORKS


def to_5bit_groups(temp_bytes:bytearray):
    numb_bits = len(temp_bytes)*8
    shift_bits = 0
    temp_number = int.from_bytes(temp_bytes)
    if numb_bits % 5 != 0:
        shift_bits = 5 - (numb_bits%5)
        temp_number = temp_number << shift_bits
        numb_bits = numb_bits + shift_bits
    iterations = numb_bits//5 
    output_bytes=[]
    for i in range(iterations):
        temp_b = (temp_number >> i*5 )& 31
        output_bytes.append(temp_b)
    return output_bytes[::-1]

def expand_hrp(add_type:str):
    temp_list=[]
    for temp_char in add_type:
        char_num = ord(temp_char)
        temp_list.append(char_num >> 5)
    temp_list.append(0)
    for temp_char in add_type:
        char_num = ord(temp_char)
        temp_list.append(char_num & 31)
    return temp_list
    
def bech32_polymod(values): # taken from https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_create_checksum(hrp,data): # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    values = expand_hrp(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (5-i)) & 31 for i in range(6)]
    
def assemble_address(hrp,data,checksum):
    temp_string = hrp+"1"
    bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    for x in data+checksum:
        temp_string += bech32_charset[x]
    return temp_string

def get_p2wpkh(pub_key,hrp):
    # sha256 and ripemd160
    temp_hash160 = hashlib.new('ripemd160',hashlib.sha256(pub_key).digest())
    print(f"Hash160 (Witness Program): {temp_hash160.digest().hex()}")

    # Assembling the address
    data = to_5bit_groups(temp_hash160.digest())
    #  insert version '0'
    data.insert(0,0)
    # check sum
    checksum = bech32_create_checksum(hrp,data)
    # final address
    address = assemble_address(hrp,data,checksum)
    return address

while True:
    try:
        my_secret = secrets.token_bytes(32)
        pk = PrivateKey(secret=my_secret,compressed=True,network=NETWORKS['signet'])
        break
    except ECError:
        print('bad secret generated')

# print(f"PrivKey WIF: {pk.wif(NETWORKS['signet'])}")
pub_key = pk.get_public_key()
enc_pub_key = pub_key.sec()
print(f"Public key: {enc_pub_key.hex()}")
p2wpkh_string = get_p2wpkh(enc_pub_key,'tb')

print(p2wpkh_string)


