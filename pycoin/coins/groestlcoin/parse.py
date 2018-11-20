from pycoin.contrib import segwit_addr
from pycoin.intbytes import int2byte
from pycoin.encoding.bytes32 import from_bytes_32
from pycoin.networks.bitcoinish import BitcoinishPayable
from pycoin.ui.Parser import parseable_str, parse_bech32, parse_colon_prefix, parse_b58, parse_b58_double_sha256

from .hash import groestlHash

def b58_groestl(s):
    data = parse_b58(s)
    if data:
        data, the_hash = data[:-4], data[-4:]
        if groestlHash(data)[:4] == the_hash:
            return data


def parse_b58_groestl(s):
    s = parseable_str(s)
    return s.cache("b58_groestl", b58_groestl)


def set_grs_parse(network):
    """Set GRS parse functions."""
    def parse_wif(s):
        data = parse_b58_groestl(s)
        if data is None or not data.startswith(network._ui._wif_prefix):
            return None
        data = data[len(network._ui._wif_prefix):]
        is_compressed = (len(data) > 32)
        if is_compressed:
            data = data[:-1]
        se = from_bytes_32(data)
        return network.Key(se, is_compressed=is_compressed)

    def parse_bip32_prv(s):
        data = parse_b58_groestl(s)
        if data is None or not data.startswith(network._ui._bip32_prv_prefix):
            return None
        return network.BIP32Node.deserialize(data)

    def parse_bip32_pub(s):
        data = parse_b58_groestl(s)
        if data is None or not data.startswith(network._ui._bip32_pub_prefix):
            return None
        return network.BIP32Node.deserialize(data)

    def parse_bip32_seed(s):
        pair = parse_colon_prefix(s)
        if pair is None or pair[0] not in "HP":
            return None
        if pair[0] == "H":
            try:
                master_secret = h2b(pair[1])
            except ValueError:
                return None
        else:
            master_secret = pair[1].encode("utf8")
        return network.BIP32Node.from_master_secret(master_secret)

    def parse_electrum_to_blob(s):
        pair = parse_colon_prefix(s)
        if pair is None or pair[0] != "E":
            return None
        try:
            return h2b(pair[1])
        except ValueError:
            return None

    def parse_electrum_seed(s):
        blob = parse_electrum_to_blob(s)
        if blob and len(blob) == 16:
            blob = b2h(blob)
            return network.ElectrumKey(
                generator=network.Key._default_generator, initial_key=blob)

    def parse_electrum_prv(s):
        blob = parse_electrum_to_blob(s)
        if blob and len(blob) == 32:
            mpk = from_bytes_32(blob)
            return network.ElectrumKey(
                generator=network.Key._default_generator, master_private_key=mpk)

    def parse_electrum_pub(s):
        blob = parse_electrum_to_blob(s)
        if blob and len(blob) == 64:
            return network.ElectrumKey(
                generator=network.Key._default_generator, master_public_key=blob)

    def parse_p2pkh(s):
        data = parse_b58_groestl(s)
        if data is None or not data.startswith(network._ui._address_prefix):
            return None
        size = len(network._ui._address_prefix)
        script = network.script_info.script_for_p2pkh(data[size:])
        script_info = network.script_info.info_for_script(script)
        return BitcoinishPayable(script_info, network)

    def parse_p2sh(s):
        data = parse_b58_groestl(s)
        if (None in (data, network._ui._pay_to_script_prefix) or
                not data.startswith(network._ui._pay_to_script_prefix)):
            return None
        size = len(network._ui._pay_to_script_prefix)
        script = network.script_info.script_for_p2sh(data[size:])
        script_info = network.script_info.info_for_script(script)
        return BitcoinishPayable(script_info, network)

    def parse_segwit(s, blob_len, script_f):
        pair = parse_bech32(s)
        if pair is None or pair[0] != network._ui._bech32_hrp or pair[1] is None:
            return None
        data = pair[1]
        version_byte = int2byte(data[0])
        decoded = segwit_addr.convertbits(data[1:], 5, 8, False)
        decoded_data = b''.join(int2byte(d) for d in decoded)
        if version_byte != b'\0' or len(decoded_data) != blob_len:
            return None
        script = script_f(decoded_data)
        script_info = network.script_info.info_for_script(script)
        return BitcoinishPayable(script_info, network)

    def parse_p2pkh_segwit(s):
        return parse_segwit(s, 20, network.script_info.script_for_p2pkh_wit)

    def parse_p2sh_segwit(s):
        return parse_segwit(s, 32, network.script_info.script_for_p2sh_wit)

    def parse_script(s):
        try:
            script = network.script_tools.compile(s)
            script_info = network.script_info.info_for_script(script)
            return BitcoinishPayable(script_info, network)
        except Exception:
            return None

    def parse_as_number(s):
        try:
            return int(s)
        except ValueError:
            pass
        try:
            return int(s, 16)
        except ValueError:
            pass

    def parse_secret_exponent(s):
        v = parse_as_number(s)
        Key = network.Key
        if v and 0 < v < Key._default_generator.order():
            return Key(secret_exponent=v)

    def parse_public_pair(s):
        point = None
        Key = network.Key
        generator = Key._default_generator
        for c in ",/":
            if c in s:
                s0, s1 = s.split(c, 1)
                v0 = parse_as_number(s0)
                if v0:
                    if s1 in ("even", "odd"):
                        is_y_odd = (s1 == "odd")
                        point = generator.points_for_x(v0)[is_y_odd]
                    v1 = parse_as_number(s1)
                    if v1:
                        if generator.contains_point(v0, v1):
                            point = generator.Point(v0, v1)
        if point:
            return Key(public_pair=point)

    def parse_sec(s):
        pair = parse_colon_prefix(s)
        if pair is not None and pair[0] == network._ui._wif_prefix:
            s = pair[1]
        try:
            sec = h2b(s)
            public_pair = sec_to_public_pair(sec, network.Key._default_generator)
            is_compressed = is_sec_compressed(sec)
            return network.Key(public_pair=public_pair, is_compressed=is_compressed)
        except Exception:
            pass

    def parse_address(s):
        s = parseable_str(s)
        return parse_p2pkh(s) or parse_p2sh(s) or parse_p2pkh_segwit(s) or parse_p2sh_segwit(s)

    def parse_payable(s):
        s = parseable_str(s)
        return parse_address(s) or parse_script(s)

    def parse_hierarchical_key(s):
        s = parseable_str(s)
        for f in [parse_bip32_seed, parse_bip32_prv, parse_bip32_pub,
                  parse_electrum_seed, parse_electrum_prv, parse_electrum_pub]:
            v = f(s)
            if v:
                return v

    def parse_private_key(s):
        s = parseable_str(s)
        for f in [parse_wif, parse_secret_exponent]:
            v = f(s)
            if v:
                return v

    def parse_secret(s):
        s = parseable_str(s)
        for f in [parse_private_key, parse_hierarchical_key]:
            v = f(s)
            if v:
                return v

    def parse_public_key(s):
        s = parseable_str(s)
        for f in [parse_public_pair, parse_sec]:
            v = f(s)
            if v:
                return v

    def parse_input(s):
        # BRAIN DAMAGE: todo
        return None

    def parse_tx(s):
        return None

    def parse(s):
        s = parseable_str(s)
        return (parse_payable(s) or
                parse_input(s) or
                parse_secret(s) or
                parse_tx(s))

    # hierarchical key
    parse.bip32_seed = parse_bip32_seed
    parse.bip32_prv = parse_bip32_prv
    parse.bip32_pub = parse_bip32_pub
    parse.electrum_seed = parse_electrum_seed
    parse.electrum_prv = parse_electrum_prv
    parse.electrum_pub = parse_electrum_pub

    # private key
    parse.wif = parse_wif
    parse.secret_exponent = parse_secret_exponent
    parse.secret = parse_secret

    # public key
    parse.public_pair = parse_public_pair
    parse.sec = parse_sec

    # address
    parse.p2pkh = parse_p2pkh
    parse.p2sh = parse_p2sh
    parse.p2pkh_segwit = parse_p2pkh_segwit
    parse.p2sh_segwit = parse_p2sh_segwit

    # payable (+ all address types)
    parse.script = parse_script

    #parse.spendable = parse_spendable
    #parse.script_preimage = parse_script_preimage

    # semantic items
    parse.hierarchical_key = parse_hierarchical_key
    parse.private_key = parse_private_key
    parse.public_key = parse_public_key
    parse.address = parse_address
    parse.payable = parse_payable
    parse.input = parse_input
    parse.tx = parse_tx

    network.parse = parse
