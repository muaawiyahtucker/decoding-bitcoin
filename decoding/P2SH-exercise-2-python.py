import hashlib, re

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

#function taken from "Programming Bitcoin" by Jimmy Song
def encode_base58(s:bytes)->str:
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    # convert to big endian integer
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def is_alphanumeric(input_string:str)->bool:
    #To test that it is a valid Hex
    pattern = r'^[a-zA-Z0-9]+$'
    return bool(re.fullmatch(pattern, input_string))

def generateP2SHAddress(redeemScript:str)->str:
    #1. Test that redeemScript is hex
    if not is_alphanumeric(redeemScript):
        return print('Error, redeem script is not hex')

    #2. Convert hex to bytes
    bytes_rs = bytes.fromhex(redeemScript)
    
    #3 Hash the redeem script using SHA256 and RIPEMD160
    hash_rs = hashlib.new('ripemd160',hashlib.sha256(bytes_rs).digest()).digest()
    
    #4 Add version byte (0x05 for P2SH) - prepend hashed script with P2SH prefix
    versionScriptHash = b'\x05'+hash_rs

    #5 Calculate checksum (first 4 bytes of double SHA256)
    checksum = hashlib.sha256(hashlib.sha256(versionScriptHash).digest()).digest()[:4]

    #6 Combine version byte, hashed script, and checksum
    binaryAddress = versionScriptHash + checksum

    #7 Encode the result in Base58
    p2shAddress = encode_base58(binaryAddress)

    # 8. Return the P2SH address
    return p2shAddress
