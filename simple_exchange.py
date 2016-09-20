from ethereum import tester, utils
from rlp.utils import decode_hex, encode_hex, ascii_chr, str_to_bytes
from ethereum import slogging
import serpent

slogging.configure(':INFO')
s = tester.state()
tokenCode = """
event Notice(s:str, x:uint256)
def init():
    self.storage[msg.sender] = 1000

def get_balance(address):
    return(self.storage[address])

def send_token(to, value):
    fromvalue = self.storage[msg.sender]
    if fromvalue >= value:
        self.storage[msg.sender] = fromvalue - value
        self.storage[to] += value
"""


exchangeCode = """
extern contract: [send_token:[int256,int256]:_]
extern contract: [get_balance:[int256]:int256]
data owner
data secret
data timeout
data source
data is_initialized
data nounce

event Notice(s:str, x:uint256)
def init():
    self.owner = msg.sender
    self.is_initialized = 0

def initialize(secret, timeout, source):
    if msg.sender == self.owner and self.is_initialized == 0:
        self.secret = secret
        self.timeout = timeout
        self.source = source
        self.is_initialized = 1

def get_nounce():
    log(type=Notice, text("!!!"), temp)
    return ( load(self.nounce, chars=2):str )

def get_secret():
    if self.is_initialized:
        return self.secret

def transfer(token:address, nounce:str):
    temp = sha3(nounce, chars=len(nounce))
    if temp == self.secret:
        save(self.nounce, nounce,chars=len(nounce))
        self.nounce = nounce
        log(type=Notice, self.nounce, self.nounce)
        token.send_token(self.owner, token.get_balance(self), sender=self)

def refund(token:address):
    if block.number > self.timeout:
        token.send_token(self.source, token.get_balance(self), sender=self)
"""
alice = tester.k0
bob = tester.k1
silverToken = s.abi_contract(tokenCode, sender=alice)
goldToken = s.abi_contract(tokenCode, sender=bob)
exchangeAlicePart = s.abi_contract(exchangeCode, sender=alice)
exchangeBobPart = s.abi_contract(exchangeCode, sender=bob)

s.mine(100)
pre_image = "10"
block_timeout = 50
exchangeAlicePart.initialize(utils.sha3(pre_image), block_timeout, utils.privtoaddr(bob), sender=alice)
exchangeBobPart.initialize(exchangeAlicePart.get_secret(), block_timeout, utils.privtoaddr(alice), sender=bob)

silverToken.send_token(exchangeBobPart.address, 500, sender=alice)
goldToken.send_token(exchangeAlicePart.address, 500, sender=bob)
exchangeAlicePart.transfer(goldToken.address, pre_image, sender=alice)
print exchangeAlicePart.get_nounce()
exchangeBobPart.transfer(silverToken.address, pre_image, sender=bob)

print silverToken.get_balance(utils.privtoaddr(alice))
print silverToken.get_balance(utils.privtoaddr(bob))

print goldToken.get_balance(utils.privtoaddr(alice))
print goldToken.get_balance(utils.privtoaddr(bob))

