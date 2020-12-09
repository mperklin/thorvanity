import sys, os.path, logging, datetime, time, hashlib, secrets, re, threading, itertools
import bech32, pycoin, bip39

from binascii import hexlify, unhexlify
from queue import Queue
from threading import Thread
from pycoin.symbols.btc import network

write_lock = threading.Lock()
save_path = 'vanity_results.txt'

class FastWriteCounter(object):
    def __init__(self):
        self._number_of_read = 0
        self._counter = itertools.count()
        self._read_lock = threading.Lock()

    def increment(self):
        next(self._counter)

    def value(self):
        with self._read_lock:
            value = next(self._counter) - self._number_of_read
            self._number_of_read += 1
        return value

def write_result(pattern, address, mnemonic):
    with write_lock:
        result = "{0}, {1}, {2}".format(pattern, address, mnemonic)
        print(result)
        with open(save_path, "a") as result_file:
            result_file.write(result)

def search(search_patterns, counter):
    found = False

    while(True):
        # Generate a random mnemonic
        random_bytes = secrets.token_bytes(nbytes=32)
        mnemonic = bip39.encode(random_bytes)

        # Get its BIP32 master seed
        seed_bytes = bip39.to_seed(mnemonic)
        master_seed = network.keys.bip32_seed(seed_bytes)

        # Derive the child key
        #thorchain_bip32_path = '44H/931H/0H/0/0'
        thorchain_bip32_path = '44H/118H/0H/0/0'
        child_key = master_seed.subkey_for_path(thorchain_bip32_path)

        # Get its thorchain address
        sec = child_key.sec()
        hash160 = child_key.hash160()
        words = bech32.convertbits(hash160, 8, 5)
        address = bech32.bech32_encode("thor", words)

        counter.increment()

        # Check it against our search patterns
        for word in search_patterns:
            pattern = word + "$"
            if re.search(pattern, address):
                write_result(pattern, address, mnemonic)
                found = True
                break

        if found:
            break

    return mnemonic

def main(argv):
    logging.basicConfig(format='%(asctime)s: %(message)s', level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')
    logging.info("Vanityminer Started")

    work_queue = Queue()
    thread_list = list()

    # bech32_alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    search_patterns = ['fuck', 'cunt', 'ass', 'sex', 'p00p', '6969', 'thor', 'rune', 'm00n', 'h0dl', 'fehu', 'jera', '0dal', '([0-9])\1{3}']
    worker_target = 10

    counter = FastWriteCounter()

    start_time = datetime.datetime.now()
    while(True):
        # Search for a thread that is finished
        done_thread = None
        for thread in thread_list:
            if not thread.is_alive():
                done_thread = thread
                break

        # Remove the thread from our list if it's done
        if done_thread:
            thread_list.remove(done_thread)

        # Get the current thread count
        thread_count = len(thread_list)

        # If we don't have enough workers
        if thread_count < worker_target:
            t = Thread(target=lambda q, arg1: q.put(search(search_patterns, counter)), args=(work_queue, search_patterns))
            t.start()
            thread_list.append(t)

        # Compile stats
        current_count = counter.value()
        current_time = datetime.datetime.now()
        timespan = current_time - start_time
        count_per_second = float(current_count) / float(timespan.total_seconds())

        # Print stats
        status_message = "Threads: {0}, {1} in {2} ({3:.1f}/s)".format(len(thread_list), current_count, timespan, count_per_second)
        print(status_message)
        time.sleep(1)

    print(mnemonic)


if __name__ == "__main__":
    main(sys.argv[1:])
