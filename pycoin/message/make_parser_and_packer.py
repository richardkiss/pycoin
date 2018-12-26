import io
import struct

from pycoin.encoding.hash import double_sha256
from pycoin.encoding.hexbytes import b2h_rev
from pycoin.satoshi.satoshi_int import parse_satoshi_int
from pycoin.satoshi.satoshi_streamer import Streamer, STREAMER_FUNCTIONS

from .InvItem import InvItem
from .PeerAddress import PeerAddress

# definitions of message structures and types
# L: 4 byte integer
# 6: 6 byte integer
# Q: 8 byte long integer
# S: unicode string encoded using utf-8
# [v]: array of InvItem objects
# [LA]: array of (L, PeerAddress) tuples
# b: boolean
# A: PeerAddress object
# B: Block object
# T: Tx object
# O: optional boolean


STANDARD_P2P_MESSAGES = {
    'version': (
        "version:L services:Q timestamp:Q remote_address:A local_address:A"
        " nonce:Q subversion:S last_block_index:L relay:O"
    ),
    'verack': "",
    'addr': "date_address_tuples:[LA]",
    'inv': "items:[v]",
    'getdata': "items:[v]",
    'notfound': "items:[v]",
    'reject': "message:S code:1 reason:S data:#",
    'getblocks': "version:L hashes:[#] hash_stop:#",
    'getheaders': "version:L hashes:[#] hash_stop:#",
    'sendheaders': "",
    'tx': "tx:T",
    'block': "block:B",
    'headers': "headers:[zI]",
    'getaddr': "",
    'mempool': "",
    'feefilter': "fee_filter_value:Q",
    'sendcmpct': "enabled:b version:Q",
    'cmpctblock': "header_hash:# nonce:Q short_ids:[6] prefilled_txs:[IT]",
    'getblocktxn': "header_hash:# indices:[I]",
    'blocktxn': "header_hash:# txs:[T]",
    # 'checkorder': obsolete
    # 'submitorder': obsolete
    # 'reply': obsolete
    'ping': "nonce:Q",
    'pong': "nonce:Q",
    'filterload': "filter:[1] hash_function_count:L tweak:L flags:b",
    'filteradd': "data:[1]",
    'filterclear': "",
    'merkleblock': (
        "header:z total_transactions:L hashes:[#] flags:[1]"
    ),
    'alert': "payload:S signature:S",
}


def standard_messages():
    return dict(STANDARD_P2P_MESSAGES)


def _recurse(level_widths, level_index, node_index, hashes, flags, flag_index, tx_acc):
    idx, r = divmod(flag_index, 8)
    mask = (1 << r)
    flag_index += 1
    if flags[idx] & mask == 0:
        h = hashes.pop()
        return h, flag_index

    if level_index == len(level_widths) - 1:
        h = hashes.pop()
        tx_acc.append(h)
        return h, flag_index

    # traverse the left
    left_hash, flag_index = _recurse(
        level_widths, level_index+1, node_index*2, hashes, flags, flag_index, tx_acc)

    # is there a right?
    if node_index*2+1 < level_widths[level_index+1]:
        right_hash, flag_index = _recurse(
            level_widths, level_index+1, node_index*2+1, hashes, flags, flag_index, tx_acc)

        if left_hash == right_hash:
            raise ValueError("merkle hash has same left and right value at node %d" % node_index)
    else:
        right_hash = left_hash

    return double_sha256(left_hash + right_hash), flag_index


def post_unpack_merkleblock(d, f):
    """
    A post-processing "post_unpack" to merkleblock messages.

    It validates the merkle proofs (throwing an exception if there's
    an error), and returns the list of transaction hashes in "tx_hashes".

    The transactions are supposed to be sent immediately after the merkleblock message.
    """
    level_widths = []
    count = d["total_transactions"]
    while count > 1:
        level_widths.append(count)
        count += 1
        count //= 2
    level_widths.append(1)
    level_widths.reverse()

    tx_acc = []
    flags = d["flags"]
    hashes = list(reversed(d["hashes"]))
    left_hash, flag_index = _recurse(level_widths, 0, 0, hashes, flags, 0, tx_acc)

    if len(hashes) > 0:
        raise ValueError("extra hashes: %s" % hashes)

    idx, r = divmod(flag_index-1, 8)
    if idx != len(flags) - 1:
        raise ValueError("not enough flags consumed")

    if flags[idx] > (1 << (r+1))-1:
        raise ValueError("unconsumed 1 flag bits set")

    if left_hash != d["header"].merkle_root:
        raise ValueError(
            "merkle root %s does not match calculated hash %s" % (
                b2h_rev(d["header"].merkle_root), b2h_rev(left_hash)))

    d["tx_hashes"] = tx_acc
    return d


def _make_parser(streamer, the_struct):
    "Return a function that parses the given structure into a dict"
    struct_items = [s.split(":") for s in the_struct.split()]
    names = [s[0] for s in struct_items]
    types = ''.join(s[1] for s in struct_items)

    def f(message_stream):
        return streamer.parse_as_dict(names, types, message_stream)
    return f


def make_post_unpack_alert(streamer):
    """
    Post-processor to "alert" message, to add an "alert_info" dictionary of parsed
    alert information.
    """
    the_struct = ("version:L relayUntil:Q expiration:Q id:L cancel:L setCancel:[L] minVer:L "
                  "maxVer:L setSubVer:[S] priority:L comment:S statusBar:S reserved:S")

    alert_submessage_parser = _make_parser(streamer, the_struct)

    def post_unpack_alert(d, f):
        d1 = alert_submessage_parser(io.BytesIO(d["payload"]))
        d["alert_info"] = d1
        return d
    return post_unpack_alert


def standard_parsing_functions(Block, Tx):
    """
    Return the standard parsing functions for a given Block and Tx class.
    The return value is expected to be used with the standard_streamer function.
    """
    def stream_block(f, block):
        assert isinstance(block, Block)
        block.stream(f)

    def stream_blockheader(f, blockheader):
        assert isinstance(blockheader, Block)
        blockheader.stream_header(f)

    def stream_tx(f, tx):
        assert isinstance(tx, Tx)
        tx.stream(f)

    def parse_int_6(f):
        b = f.read(6) + b'\0\0'
        return struct.unpack(b, "<L")[0]

    def stream_int_6(f, v):
        f.write(struct.pack(v, "<L")[:6])

    more_parsing = [
        ("A", (PeerAddress.parse, lambda f, peer_addr: peer_addr.stream(f))),
        ("v", (InvItem.parse, lambda f, inv_item: inv_item.stream(f))),
        ("T", (Tx.parse, stream_tx)),
        ("B", (Block.parse, stream_block)),
        ("z", (Block.parse_as_header, stream_blockheader)),
        ("1", (lambda f: struct.unpack("B", f.read(1))[0], lambda f, v: f.write(struct.pack("B", v)))),
        ("6", (parse_int_6, stream_int_6)),
        ("O", (lambda f: True if f.read(1) else False,
               lambda f, v: f.write(b'' if v is None else struct.pack("B", v)))),
    ]
    all_items = list(STREAMER_FUNCTIONS.items())
    all_items.extend(more_parsing)
    return all_items


def standard_streamer(parsing_functions, parse_satoshi_int=parse_satoshi_int):
    """
    Create a satoshi_streamer, which parses and packs using the bitcoin protocol
    (mostly the custom way arrays and integers are parsed and packed).
    """
    streamer = Streamer()
    streamer.register_array_count_parse(parse_satoshi_int)
    streamer.register_functions(parsing_functions)
    return streamer


def standard_message_post_unpacks(streamer):
    """
    The standard message post-processors: one for the version message,
    one for the alert message, and one for the merkleblock message.
    """
    return dict(alert=make_post_unpack_alert(streamer), merkleblock=post_unpack_merkleblock)


def make_parser_and_packer(streamer, message_dict, message_post_unpacks):
    """
    Create a parser and a packer for a peer's network messages.

    streamer:
        used in conjunction with the message_dict. The message_dict turns a message into
        a string specifying the fields, and this dictionary specifies how to pack or unpack
        fields to or from bytes
    message_dict:
        a dictionary specifying how to pack or unpack the various messages like "version"
    message_post_unpacks:
        a dictionary specifying functions to call to postprocess message to, for example
        extract submessages, like in "alert"
    """
    message_parsers = dict((k, _make_parser(streamer, v)) for k, v in message_dict.items())

    def parse_from_data(message_name, data):
        message_stream = io.BytesIO(data)
        parser = message_parsers.get(message_name)
        if parser is None:
            raise KeyError("unknown message: %s" % message_name)
        d = parser(message_stream)
        post_unpack = message_post_unpacks.get(message_name)
        if post_unpack:
            d = post_unpack(d, message_stream)
        return d

    def pack_from_data(message_name, **kwargs):
        the_struct = message_dict[message_name]
        if not the_struct:
            return b''
        f = io.BytesIO()
        the_fields = the_struct.split(" ")
        pairs = [t.split(":") for t in the_fields]
        for name, type in pairs:
            if type[0] == '[':
                streamer.stream_struct("I", f, len(kwargs[name]))
                for v in kwargs[name]:
                    if not isinstance(v, (tuple, list)):
                        v = [v]
                    streamer.stream_struct(type[1:-1], f, *v)
            else:
                streamer.stream_struct(type, f, kwargs[name])
        return f.getvalue()

    return parse_from_data, pack_from_data
