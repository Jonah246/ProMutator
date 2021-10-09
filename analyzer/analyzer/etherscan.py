import requests
import json

from .config import ETHERSCAN_API_KEY, CHAIN_TYPE

if CHAIN_TYPE == 'BSC':
    ETHERSCAN_URL = 'https://api.bscscan.com/api'
else:
    ETHERSCAN_URL = 'https://api.etherscan.io/api'

# ETHERSCAN_API_KEY = 'CUDFJTJMKJT36HW5ZNW6CZRD3HBZ48G9E2'

def get_contract_source_from_adr(adr):
    BASE_URL = ETHERSCAN_URL
    data = {
        'module': 'contract',
        'action': 'getsourcecode',
        'address': adr,
        'apikey': ETHERSCAN_API_KEY
    }
    return requests.get(ETHERSCAN_URL, params=data)


def get_contract_abi_from_adr(adr):
    data = {
        'module': 'contract',
        'action': 'getabi',
        'address': adr,
        'apikey': ETHERSCAN_API_KEY
    }
    return requests.get(ETHERSCAN_URL, params=data)

# Fetches implemenation's abi if its proxy contract


def get_proxy_contract(adr):
    r = get_contract_source_from_adr(adr)
    data = r.json()['result'][0]
    if 'Proxy' in data.keys() and data['Proxy'] == '1':
        return {'abi': get_contract_abi_from_adr(data['Implementation']).json()['result'], 'contract_name': data['ContractName']}
    return {'abi': data['ABI'], 'contract_name': data['ContractName']}
