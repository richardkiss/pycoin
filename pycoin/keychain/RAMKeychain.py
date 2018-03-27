from collections import defaultdict


class RAMKeychain(object):
    def __init__(self):
        self._lookup = {}
        self.clear_secrets()

    def add_key_paths(self, key, path_iterator=[""], use_uncompressed=None):
        fingerprint = key.fingerprint()
        for path in path_iterator:
            hash160 = key.subkey_for_path(path).hash160(use_uncompressed=use_uncompressed)
            self._lookup[hash160] = (fingerprint, path)
            print(path, fingerprint, hash160)

    def path_for_hash160(self, hash160):
        return self._lookup.get(hash160)

    def get(self, hash160):
        if hash160 in self._secret_exponent_cache:
            return self._secret_exponent_cache[hash160]

        v = self.path_for_hash160(hash160)
        if not v:
            return

        fingerprint, path = v
        for key in self._secrets.get(fingerprint):
            subkey = key.subkey_for_path(path)
            h1 = subkey.hash160(use_uncompressed=False)
            self._secret_exponent_cache[h1] = subkey
            h2 = subkey.hash160(use_uncompressed=True)
            self._secret_exponent_cache[h2] = subkey
            if hash160 in self._secret_exponent_cache:
                return self._secret_exponent_cache[hash160]

    def set_secrets(self, private_keys):
        self._secrets = defaultdict(set)
        for key in private_keys:
            self._secrets[key.fingerprint()].add(key)

    def clear_secrets(self):
        self._secrets = {}
        self._secret_exponent_cache = {}
