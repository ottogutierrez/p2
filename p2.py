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
    
def polymod(data):
    print('polymod function here')

while True:
    try:
        my_secret = secrets.token_bytes(32)
        pk = PrivateKey(secret=my_secret,compressed=True,network=NETWORKS['signet'])
        break
    except ECError:
        print('bad secret generated')

print(f"PrivKey WIF: {pk.wif(NETWORKS['signet'])}")
pub_key = pk.get_public_key()
enc_pub_key = pub_key.sec()
print(f"Public key: {enc_pub_key.hex()}")

# sha256 and ripemd160
temp_hash160 = hashlib.new('ripemd160',hashlib.sha256(enc_pub_key).digest())
print(f"Hash160 (Witness Program): {temp_hash160.digest().hex()}")

# Assembling the address
bech32_bytes = to_5bit_groups(temp_hash160.digest())
#  insert version '0'
bech32_bytes.insert(0,0)
# address type
address_type = expand_hrp('tb')
# hrp + address
values = address_type + bech32_bytes
print(polymod(values))

