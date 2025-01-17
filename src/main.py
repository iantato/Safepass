
from safepass.crypto.pbkdf2 import MasterKey

username = 'Ian'
password = '1234'

_master_key = MasterKey(username, password)
print(_master_key.get_key())