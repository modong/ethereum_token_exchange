# P2P Token Exchange Contract

## Introduction
Ethereum provides the capability to program smart contract and a typical use case for smart contract is to issue new cryptocurrency based on  Ethereum blockchain, for example REP in Augur and SINGL in Singular DTV. Tokens can be exchanged in centralized exchanges like poloniex, but the centralized exchanges always charges for a fee and acting as a central point of failure if the exchange is hacked (e.g. bitfinex recently and Mt.Gox a while ago). This is especially bad for bulk exchanges of cryptocurrency where the fee value is high and the risk of default is high.  There is also a concern about privacy that the exchange knows some information about the token holder usually. 

It is apparently useful to have a method to securely and efficiently exchange different tokens derived from Ethereum. Therefore, this smart contract project targets this use case to implement a P2P exchange contract.

## Use Case Scenario

We consider a use case where two parties, let’s say Alice and Bob, are involved. Each of them holds some cryptocurrency implemented on Ethereum. We assume Alice and Bob has negotiated a price to exchange their tokens off blockchain and do not want to use a centralized exchange. However, they do not trust each other so they would like to do this securely.

We assume the token contract looks like the following:

```python
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
```

The above is a pretty simple token contract with `send_token` as the only interesting function to send token from some address to some other address. `send_token` has a basic sanity check of balance validity. Let's say Alice has silverToken and Bob has goldToken. 

## Design goals

The naiive solution of using a pair of `send_token` calls between Alice and Bob does not work because there is no way to guarantee whoever transferred the value first would not be "hassled" by the other party. Using a third party escrow solves the problem but it is not scalable and involves new trust issues about the escrow and additional costs of escrow fees. Therefore, we would like to have a smart-contract-only solution that achieve the following design goals:

1. Either transfers happen in both directions or no transfer happens.
2. No token will get locked up if one party decides to abort exchange in the middle of the exchange process

## Implementation

### Exchange contract
Using the following exchange contract with a certain sequence of actions guarantees the above two design goals.

```python
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

def test_callstack(): 
    return(1)

def initialize(secret, timeout, source, peer:address, token:address):
    if self.test_callstack() != 1: 
        return(-1)
    if msg.sender == self.owner and self.is_initialized == 0:
        self.secret = secret
        self.timeout = timeout
        self.source = source
        self.is_initialized = 1
        self.peer = peer
        self.token = token

def get_secret():
    if self.test_callstack() != 1: 
        return(-1)
    if self.is_initialized:
        return self.secret

def transfer(nounce:str):
    if self.test_callstack() != 1: 
        return(-1)
    temp = sha3(nounce, chars=len(nounce))
    if temp == self.secret and block.number < self.timeout:
        self.token.send_token(self.owner, self.token.get_balance(self), sender=self)
        if self.peer != 0:
            self.peer.transfer(nounce)

def refund(token:address):
    if self.test_callstack() != 1: 
        return(-1)
    if block.number > self.timeout:
        token.send_token(self.source, token.get_balance(self), sender=self)
"""

```

## Operation Sequence


### Normal Case
Let's say Alice and Bob agree to exchange their token at the ratio of 1:1 and the amount of exchange is 500 tokens. They would need to follow the following sequence of operations denoted by the following code:
```python
# Initialization of two tokens
alice = tester.k0
bob = tester.k1
silverToken = s.abi_contract(tokenCode, sender=alice)
goldToken = s.abi_contract(tokenCode, sender=bob)

# Alice first deploy an exchange contract
exchangeAlicePart = s.abi_contract(exchangeCode, sender=alice)

# Bob deploy the same exchange contract
exchangeBobPart = s.abi_contract(exchangeCode, sender=bob)

# This is a private information for Alice acting as a "password" 
# to unlock the fund hold in exchange contract later
password = "10"

# This is used to guarantee no fund get locked in the contract if one or both decide to abort the exchange
block_timeout = 50

# Alice will initialize the exchange contract with the hash of the password as secret and specify the 
# timeout value and the source of the fund that is about to be put into the exchange contract
# It also specify what is the peer (exchangeBobPart) of this contract 
# and what is the token contract address
exchangeAlicePart.initialize(utils.sha3(pre_image), block_timeout, utils.privtoaddr(bob), exchangeBobPart.address, goldToken.address, sender=alice)

# Bob will do the exact same thing as Alice, only difference is that he will specify the Alice 
# as the source of the fund that is about to be put into the exchange contract
# Bob's part will not specify a peer exchange contract but only specify the token contract
exchangeBobPart.initialize(exchangeAlicePart.get_secret(), block_timeout, utils.privtoaddr(alice), 0, silverToken.address, sender=bob)


# Alice at this point can check if Bob has specified her as source and also the secret
# matches exchangeAlicePart's secret. 

# If it does, Alice will send 500 tokens of silverToken to the contract exchangeBobPart
silverToken.send_token(exchangeBobPart.address, 500, sender=alice)

# After seeing this, Bob will send 500 tokens of goldToken to contract exchangeAlicePart
goldToken.send_token(exchangeAlicePart.address, 500, sender=bob)

# Alice will unlock the fund by passing the password to the exchangeContract and call
# transfer function. Since the passowrd's hash matches the secret, the fund is released to
# Alice and at the same time, Alice's contract calls Bob's contract to release token to Bob.
exchangeAlicePart.transfer(goldToken.address, password, sender=alice)

# Exchange process is done
print silverToken.get_balance(utils.privtoaddr(alice))
print silverToken.get_balance(utils.privtoaddr(bob))
print goldToken.get_balance(utils.privtoaddr(alice))
print goldToken.get_balance(utils.privtoaddr(bob))
```

The above contract apparently satisfies the first goal, because Alice is the one who deposit token first to Bob and as soon as she reveals the password, Bob automatically receives the fund deposited by Alice. Bob will also not get away with Alice's money, because if he does not deposit to Alice's exchange contract, Alice will never release the password.

The second design goal is also guaranteed because there is a timeout value in the contract, if one party drops out during any point of the process with one or both party already deposited token to the contracts, the original owner can retrieve the tokens after the timeout. This is the use of `time_out` and `source` data member in the exchange contract.

### Adversary Case

1. Alice wants to get Bob's token without paying Bob. This is not possible because Alice need to first deposit to Bob's contract and two contracts are using the same transfer function. Therefore, she cannot get away with Bob's token.

2.Bob wants to get Alice's token without paying Alice.
This is also not possible because Bob is the passive party (market maker) and he need Alice to call the transfer function to get Alice's token. He also would need to use the same secret as Alice used, otherwise Alice will not deposit her token into his contract.

3. Money get locked forever
This would not happen because we have the refund mechanism in the contract. 

## Limitations

1. Sloth Attack:
An "Sloth" Attack is possible that Bob just never pays to the Alice's contract. In this case, Alice will suffer loss from spending gas on transferring her token to Bob's account and later refund it. This attack is hard to prevent because two parties are executing code sequetially and therefore, someone can drop out at some point that is unfair for the other. Ethereum should have some data base transaction-like excution to make it work. Another potential solution for this is to have an insurance party involved in these transactions to cover the potential violation.

## Total Gas Cost

1294877 gas for normal full execution
