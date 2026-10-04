import secrets

from embit.ec import ECError, PrivateKey
from embit.networks import NETWORKS

while True:
    try:
        my_secret = secrets.token_bytes(32)
        pk = PrivateKey(secret=my_secret,compressed=True,network=NETWORKS['signet'])
        break
    except ECError:
        print('bad secret generated')

print(f"PrivKey WIF: {pk.wif(NETWORKS['signet'])}")
pubKey = pk.get_public_key()
print(f"Public key: {pubKey.sec().hex()}")