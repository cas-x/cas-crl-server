from oscrypto import asymmetric

import os

a = ""
with open("./test.key", "r") as f:
    a = f.read()
private_key = asymmetric.load_private_key(a)
print(a)
print(private_key)
