import asyncio
from ic.agent import Agent  # Specify the required classes/functions
from ic.identity import Identity, Principal  # Specify the required classes/functions
from ic.client import Client  # Specify the required classes/functions
from ic.candid import Types, encode  # Keep as is
import time

client = Client()
iden = Identity(privkey="833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
print('principal:', Principal.self_authenticating(iden.der_pubkey))
ag = Agent(iden, client)

start = time.time()
# query token totalSupply
ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", encode([]))
print('totalSupply:', ret)

# query token name
ret = ag.query_raw("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
print('name:', ret)

# query token balance of user
ret = ag.query_raw(
        "gvbup-jyaaa-aaaah-qcdwa-cai",
        "balanceOf",
        encode([
            {'type': Types.Principal, 'value': iden.sender().bytes}
        ])
      )
print('balanceOf:', ret)

# transfer 100 tokens to blackhole
ret = ag.update_raw(
        "gvbup-jyaaa-aaaah-qcdwa-cai",
        "transfer",
        encode([
            {'type': Types.Principal, 'value': 'aaaaa-aa'},
            {'type': Types.Nat, 'value': 10000000000}
            ])
        )
print('result: ', ret)

t = time.time()
print("sync call elapsed: ", t - start)

async def test_async():
    ret = await ag.query_raw_async("gvbup-jyaaa-aaaah-qcdwa-cai", "totalSupply", encode([]))
    print('totalSupply:', ret)

    # query token name
    ret = await ag.query_raw_async("gvbup-jyaaa-aaaah-qcdwa-cai", "name", encode([]))
    print('name:', ret)

    # query token balance of user
    ret = await ag.query_raw_async(
            "gvbup-jyaaa-aaaah-qcdwa-cai",
            "balanceOf",
            encode([
                {'type': Types.Principal, 'value': iden.sender().bytes}
            ])
        )
    print('balanceOf:', ret)

    # transfer 100 tokens to blackhole
    ret = await ag.update_raw_async(
            "gvbup-jyaaa-aaaah-qcdwa-cai",
            "transfer",
            encode([
                {'type': Types.Principal, 'value': 'aaaaa-aa'},
                {'type': Types.Nat, 'value': 10000000000}
                ])
            )
    print('result: ', ret)

asyncio.run(test_async())
print("sync call elapsed: ", time.time() - t)