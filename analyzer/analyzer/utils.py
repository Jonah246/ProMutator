from logging import error, raiseExceptions
from .etherscan import get_proxy_contract
from .config import WEB3_IPC_PATH, CHAIN_TYPE, WEB3_TIMEOUT
import web3
from web3 import Web3


def initiate_w3():
    if WEB3_IPC_PATH != '':
        return Web3(Web3.IPCProvider(WEB3_IPC_PATH, timeout=WEB3_TIMEOUT))
    else:
        if CHAIN_TYPE == 'BSC':
            return Web3(
                Web3.HTTPProvider(
                    'https://bsc-dataseed1.ninicoin.io/', request_kwargs={'timeout': WEB3_TIMEOUT}))
        else:
            raise Exception('should prvoide rpc endpoint')


# w3 = Web3(Web3.IPCProvider(WEB3_IPC_PATH, timeout=200))
w3 = initiate_w3()

from web3.middleware import geth_poa_middleware
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

import re


target_code_hash = [

]


def check_target_code_hash(address):
    adr = w3.toChecksumAddress(address)
    if adr not in adr_ch_dict.keys():
        adr_ch_dict[adr] = get_adr_code_hash(adr).hex()

    ch = adr_ch_dict[adr]
    if ch in target_code_hash:
        return True
    return False


contract_dict = {}
adr_ch_dict = {}


def set_contract(code_hash, contract):
    contract_dict[code_hash] = contract


def get_contract(code_hash):
    if code_hash in contract_dict.keys():
        return contract_dict[code_hash]


class Contract():
    def get_eth_contract(self, address):
        code_hash = get_adr_code_hash(address)
        contract = get_contract(code_hash)
        if contract != None:
            return w3.eth.contract(abi=contract.abi, address=address)

        try:
            etherscan_contract = get_proxy_contract(address)
        except Exception as e:
            print(e)
            return None

        if etherscan_contract['abi'] == 'Contract source code not verified':
            return None

        contract = w3.eth.contract(
            abi=etherscan_contract['abi'], address=address)
        set_contract(code_hash, contract)
        return contract

    def __init__(self, contract_address, check_implementation=False):
        # print("contractadr", contract_address)
        self.contract_address = contract_address
        self.address = contract_address
        self.is_proxy = False

        self._contract = self.get_eth_contract(
            w3.toChecksumAddress(contract_address))
        # self.contract_name = etherscan_contract['contract_name']
        if self._contract == None:
            self.abi = 'Contract source code not verified'
            return
        self.abi = self._contract.abi
        # else:
        #     self.contract_name = 'none'
        #     self.abi = 'none'

    def decode_input(self, i):
        if self.abi == 'Contract source code not verified':
            return i
        try:
            return self._contract.decode_function_input(i)
        except Exception as e:
            pass
        return i

            
            
def get_adr_code_hash(address):
    adr = w3.toChecksumAddress(address)
    code =  w3.eth.getCode(adr)
    code_hash = w3.sha3(hexstr=code.hex())
    return code_hash


## adr code hash dict

def get_code_from_adr(adr):
    adr = w3.toChecksumAddress(adr)
    if adr not in adr_ch_dict.keys():
        adr_ch_dict[adr] = get_adr_code_hash(adr).hex()
    
    ch = adr_ch_dict[adr]
    if ch not in contract_dict.keys():
        search_adr_code(adr)
    return contract_dict[ch]

        
def search_adr_code(address):
    address = w3.toChecksumAddress(address)
    code_hash = get_adr_code_hash(address)
    if code_hash.hex() not in contract_dict.keys():
        contract_dict[code_hash.hex()] = Contract(address)
    else:
        print('address: {} has same code as {}, {}'.format(
            address, contract_dict[code_hash.hex()].contract_address,
            contract_dict[code_hash.hex()].contract_name
        ))


def get_revert_reason(output):
    shrimp_output = re.sub('00', '', output[138:])
    if len(shrimp_output) % 2 != 0:
        shrimp_output = shrimp_output + '0'
    try:
        msg = Web3.toText(shrimp_output)
        return msg
    except:
        return output

def parse_traces(traces, depth=0):
    if traces is None:
        return
    to_adr = traces['to']
    contract = get_code_from_adr(to_adr)
    from_contract = get_code_from_adr(traces['from'])

    calls = []
    err = ''
    if 'error' in traces.keys():
        err = traces['error']
        if 'output' in traces.keys():
#             print('output', traces['output'])
            try:
                err = {
                    'error': err,
                    'message': get_revert_reason(traces['output']),
                }
#                 print(err)
            except:
                pass
    if 'calls' in traces.keys():
        for call in traces['calls']:
            calls.append(parse_traces(call, depth + 1))

    parsed_call = { 
        'from': traces['from'],
        'from_contract': from_contract.contract_name,
        'to': traces['to'],
        'to_name': contract.contract_name,
        'calls': calls,
        'error': err,
    }

    if 'input' in traces.keys():
        parsed_call['input'] = contract.decode_input(traces['input'])
        parsed_call['raw_input'] = traces['input']
    
    if 'output' in traces.keys():
        parsed_call['output'] = traces['output']

    return parsed_call
