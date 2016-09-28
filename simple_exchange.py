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
extern contract: [transfer:[bytes]:_]
extern contract: [get_balance:[int256]:int256]
data owner
data secret
data timeout
data source
data is_initialized
data peer
data token

event Notice(s:str, x:uint256)
def init():
    self.owner = msg.sender
    self.is_initialized = 0

def initialize(secret, timeout, source, peer:address, token:address):
    if msg.sender == self.owner and self.is_initialized == 0:
        self.secret = secret
        self.timeout = timeout
        self.source = source
        self.is_initialized = 1
        self.peer = peer
        self.token = token

def get_secret():
    if self.is_initialized:
        return self.secret

def transfer(nounce:str):
    temp = sha3(nounce, chars=len(nounce))
    if temp == self.secret and block.number < self.timeout:
        self.token.send_token(self.owner, self.token.get_balance(self), sender=self)
        if self.peer != 0:
            self.peer.transfer(nounce)

def refund(token:address):
    if block.number > self.timeout:
        token.send_token(self.source, token.get_balance(self), sender=self)
"""


def normal_case():
    alice = tester.k0
    bob = tester.k1
    silverToken = s.abi_contract(tokenCode, sender=alice)
    goldToken = s.abi_contract(tokenCode, sender=bob)
    exchangeAlicePart = s.abi_contract(exchangeCode, sender=alice)
    exchangeBobPart = s.abi_contract(exchangeCode, sender=bob)
    
    print "Before exchange happens" 
    print "Alice has {token} silver token".format(token=silverToken.get_balance(utils.privtoaddr(alice)))
    print "Bob has {token} silver token".format(token=silverToken.get_balance(utils.privtoaddr(bob)))
    
    print "Alice has {token} gold token".format(token=goldToken.get_balance(utils.privtoaddr(alice)))
    print "Bob has {} gold token".format(goldToken.get_balance(utils.privtoaddr(bob)))
    pre_image = "10"
    block_timeout = 50
    exchangeAlicePart.initialize(utils.sha3(pre_image), block_timeout, utils.privtoaddr(bob), exchangeBobPart.address, goldToken.address, sender=alice)
    exchangeBobPart.initialize(exchangeAlicePart.get_secret(), block_timeout, utils.privtoaddr(alice), 0, silverToken.address, sender=bob)
    silverToken.send_token(exchangeBobPart.address, 500, sender=alice)
    goldToken.send_token(exchangeAlicePart.address, 500, sender=bob)
    exchangeAlicePart.transfer(pre_image, sender=alice)
    print "" 
    print ""
    print "After exchange happens" 
    print "Alice has {token} silver token".format(token=silverToken.get_balance(utils.privtoaddr(alice)))
    print "Bob has {token} silver token".format(token=silverToken.get_balance(utils.privtoaddr(bob)))
    
    print "Alice has {token} gold token".format(token=goldToken.get_balance(utils.privtoaddr(alice)))
    print "Bob has {} gold token".format(goldToken.get_balance(utils.privtoaddr(bob)))


if __name__ == "__main__":
    normal_case()
