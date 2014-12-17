from flask import Flask, request
from Crypto.Hash import SHA, HMAC
from time import sleep

app = Flask(__name__)

secret_key = b'THIS IS SO SECRETTTT'

# custom version
def sha_hmac(key, msg):
  trans_5C = bytearray((x ^ 0x5c) for x in range(256))
  trans_36 = bytearray((x ^ 0x36) for x in range(256))
  hasher = SHA.new()

  if len(ken) > 64:
    hasher.update(key)
    key = hasher.hexdigest()

  key = key + bytearray(64 - len(key))
  o_key_pad = key.translate(trans_5C)
  i_key_pad = key.translate(trans_36)

  hasher = SHA.new()
  hasher.update(i_key_pad + msg)
  x = hasher.hexdigest()
  hasher = SHA.new()
  hasher.update(o_key_pad + x)

  return hasher.hexdigest()

def insecure_compare(msg, sig):
  hmac = HMAC.new(secret_key, msg.encode('ascii'), SHA)
  hmac = hmac.hexdigest()

  sig_bytes = bytes.fromhex(sig)
  hmac_bytes = bytes.fromhex(hmac)

  print(hmac)
  print(sig)

  for i in range(len(sig_bytes)):
    if sig_bytes[i] != hmac_bytes[i]:
      return False
    sleep(0.05)

  return True

def insecure_compare_32(msg, sig):
  hmac = HMAC.new(secret_key, msg.encode('ascii'), SHA)
  hmac = hmac.hexdigest()

  sig_bytes = bytes.fromhex(sig)
  hmac_bytes = bytes.fromhex(hmac)

  for i in range(len(sig_bytes)):
    if sig_bytes[i] != hmac_bytes[i]:
      return False
    sleep(0.005)

  return True

@app.route("/crypto32")
def crypto32():
  file = request.args.get('file')
  sig = request.args.get('signature')
  valid = insecure_compare_32(file, sig)
  return "Correct" if valid else "Request is invalid", 500

@app.route("/crypto")
def crypto():
  file = request.args.get('file')
  sig = request.args.get('signature')
  valid = insecure_compare(file, sig)
  return "Correct" if valid else "Request is invalid", 500

if __name__ == "__main__":
    app.run(port=8081, debug=True)
