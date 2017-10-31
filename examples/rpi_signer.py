#!/usr/bin/env python

# this script fetches unsigned transactions and signs them
# it is intended to run on a Raspberry pi
# to run elsewhere, remove all the LED stuff

import argparse
import io
import logging
import os
import random
import re
import subprocess
import sys
import time

from threading import Thread

from pycoin.key import Key
from pycoin.key.BIP32Node import BIP32Node
from pycoin.key.validate import is_address_valid, is_private_bip32_valid, is_wif_valid
from pycoin.encoding import bitcoin_address_to_hash160_sec
from pycoin.serialize import b2h, h2b
from pycoin.tx import tx_utils
from pycoin.tx.Tx import Tx

import requests

logger = logging.getLogger(__name__)


def sign_tx(tx, tx_info, bip32_db, key_db):
    wifs = [bip32_db.get(kp.get("key_fingerprint")).subkey_for_path(kp["key_path"]).wif()
            for kp in tx_info["key_paths"]]
    misc_addresses = tx_info.get("misc_addresses", [])
    extra_wifs = [key_db.get(a) for a in misc_addresses if a in key_db]
    wifs.extend(extra_wifs)
    tx_utils.sign_tx(tx, wifs=wifs)


def process_tx_info(url, tx_info, bip32_db, key_db, verify):
    start_time = time.time()
    hex_string = tx_info.get("tx_hex")
    f = io.BytesIO(h2b(hex_string))
    tx = Tx.parse(f)
    tx.parse_unspents(f)
    tx_id = tx_info.get("id")
    logger.info("signing tx id %s with %d input(s)", tx_info.get("id"), len(tx.txs_in))

    sign_tx(tx, tx_info, bip32_db, key_db)
    end_time = time.time()
    total_time = end_time - start_time
    logger.info("%s %s: %s" % (tx_id, tx.id(), tx.as_hex()))
    logger.info("took %3.2f seconds (%3.2f s per input)", total_time, total_time / len(tx.txs_in))
    r = requests.post(url, json=dict(btx_id=tx_id, btx_hex=tx.as_hex()), verify=verify)
    return r


def process(url, tx_info_list, bip32_db, key_db, verify):
    """
    tx_info_list:
        a list of tx_info items where
        tx_info is a dict:
            tx_hex: hex dump of tx
            id: transaction id (ie. tx.id())
            key_paths: a list of {"key_fingerprint": "(hex)", "key_path": "1/3"} dicts
    """
    results = []
    for tx_info in tx_info_list:
        r = process_tx_info(url, tx_info, bip32_db, key_db, verify)
        results.append(r)
    return results


def read_wifs(string_iterator):
    wifs = []
    key_db = dict()
    bip32_keys = []
    for l in string_iterator:
        line_wifs = []
        hash160 = None
        for t in l.split():
            if is_address_valid(t):
                hash160 = bitcoin_address_to_hash160_sec(t)
            elif is_wif_valid(t):
                line_wifs.append(t)
            elif is_private_bip32_valid(t):
                bip32_keys.append(BIP32Node.from_hwif(t))
            else:
                logger.error("unknown item %s" % t)
        if hash160 and len(line_wifs) == 1:
            key_db[hash160] = line_wifs[0]
        else:
            wifs.extend(line_wifs)
    return wifs, key_db, bip32_keys


def init_led():
    PATH = "/sys/class/leds/led0/trigger"
    if not os.path.exists(PATH):
        return
    f = open(PATH, "w")
    f.write("none")
    f.close()


def set_led_state(is_on):
    PATH = "/sys/class/leds/led0/brightness"
    if not os.path.exists(PATH):
        return
    f = open(PATH, "w")
    f.write("1" if is_on else "0")
    f.close()


def morse_code(text, f_off=lambda: set_led_state(0), f_on=lambda: set_led_state(1), DOT=0.30):
    morsetab = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..',
        '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
        '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        ',': '--..--', '.': '.-.-.-', '?': '..--..', ';': '-.-.-.', ':': '---...',
        "'": '.----.', '-': '-....-', '/': '-..-.', '(': '-.--.-', ')': '-.--.-',
        '_': '..--.-', ' ': ' ',
    }
    DAH = 3 * DOT
    f_off()
    for t in text.upper():
        for code in morsetab.get(t, " "):
            if code in ".-":
                f_on()
                if code is ".":
                    time.sleep(DOT)
                else:
                    time.sleep(DAH)
            else:
                time.sleep(DAH+DOT)
            f_off()
            time.sleep(DOT)
        time.sleep(DAH)



def create_morse_subthread(message_array):
    init_led()

    class MorseThread(Thread):
        def __init__(self, message):
            super(MorseThread, self).__init__()
            self.message = message

        def run(self):
            while self.message:
                morse_code(''.join(self.message))
                time.sleep(1)

    MorseThread(message_array).start()


def get_ip():
    output = subprocess.check_output("ifconfig").decode("utf8")
    m = re.search(r"inet addr:([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})  Bcast:", output)
    if m:
        return m.group(1)
    return "?"


def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format=('%(asctime)s [%(process)d] [%(levelname)s] '
                '%(filename)s:%(lineno)d %(message)s')
    )
    logger.setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser(description='fetch and sign transactions')
    parser.add_argument('url', type=str, help='the URL to GET and POST')
    parser.add_argument('keyfile', type=argparse.FileType('r'), default=sys.stdin,
                        help='the file or pipe that BIP32 and WIF keys are read from')
    parser.add_argument('--led', action='store_true', help='enable LED morse code blinking on Raspberry Pi')
    parser.add_argument('--verify', action='store_true', help='verify SSL certificates')
    parser.add_argument('-b', '--batch-size', type=int, default=2, help='number of transactions to sign each iteration')
    parser.add_argument('--cmd', nargs="*", type=str, help='command to run after keys are read')
    args = parser.parse_args()

    MESSAGE = ["S"]
    if args.led:
        MESSAGE[:] = get_ip()
        create_morse_subthread(MESSAGE)

    url = args.url

    keyfile = args.keyfile
    logger.info("loading wifs from %s", keyfile.name)
    wifs, key_db, bip32_keys = read_wifs(keyfile)
    logger.info("done loading wifs from %s", keyfile.name)
    if len(key_db) + len(bip32_keys) + len(wifs) == 0:
        logger.info("no keys found, exiting")
        MESSAGE[:] = ''
        sys.exit(1)
    for wif in wifs:
        key = Key.from_text(wif)
        key_db[key.hash160()] = wif

    for cmd in args.cmd or []:
        subprocess.check_call(cmd, shell=True)

    bip32_db = dict((b2h(b32.fingerprint()), b32) for b32 in bip32_keys)
    while 1:
        try:
            r = requests.get(url, verify=args.verify)
            MESSAGE[:] = "OK"
            tx_info_list = r.json()
            if len(tx_info_list) > 0:
                # choose two at random
                random.shuffle(tx_info_list)
                process(url, tx_info_list[:args.batch_size], bip32_db, key_db, args.verify)
                MESSAGE[:] = "G"
            else:
                time.sleep(15)
        except Exception:
            logger.exception("problem looping")
            MESSAGE[:] = "X"
            time.sleep(15)


if __name__ == '__main__':
    main()
