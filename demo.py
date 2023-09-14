
from gmssl import *

sm3 = Sm3()
sm3.update(b'abc')
dgst = sm3.digest()
print("sm3('abc') : " + dgst.hex())
