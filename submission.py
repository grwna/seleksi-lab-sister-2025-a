import hashlib
import base64
import pyspx.sha2_256f
import requests
import json
import sys
import pyotp
import random

# THIS IS JUST A TEMPLATE THAT THE SERVER STORES
creds = {
    "username": "13523035",
    "password": "rayhan",
    "totp_secret": "aerith",
    "pow_prefix": "13523035:if:rayhan",
    "status": "pending"
}

url = "http://104.214.186.131:8000"

sphincs = pyspx.sha2_256f   

def find_nonce():
    pow_prefix = creds["pow_prefix"]
    difficulty = 5
    target = "0" * difficulty

    nonce = 0
    while True:
        to_hash = f"{pow_prefix}:{nonce}"
        hashed = hashlib.sha256(to_hash.encode()).hexdigest()
        if hashed[:5] == target:
            print(f"Found nonce: {nonce}")
            print(f"Hash: {hashed}")
            return nonce
        nonce += 1

def generate_keys():
        public_key, private_key = sphincs.generate_keypair(random.randbytes(96))
        
        print(f"Public Key (hex): {public_key.hex()[:32]}...")
        print(f" Length: {int.from_bytes(public_key).bit_length()}, Hash Length: {len(public_key.hex())}" )
        print(f"Private Key (hex): {private_key.hex()[:32]}...")
        print(f" Length: {int.from_bytes(private_key).bit_length()}, Hash Length: {len(private_key.hex())}" )
        
        return public_key, private_key

def validate_keys(pub, priv):
    try:
        test_message = b"Key validation test"
        signature = sphincs.sign(test_message, priv)
        sphincs.verify(test_message, signature, pub)
        print("Key pair is valid.\n")
    except Exception as e:
        print(f"Key pair is INVALID. Error: {e}")
        exit()

def activate_account(nonce, public_key):
    payload = {
        "username": "13523035",
        "password": "rayhan",
        "nonce":nonce,
        "public_key": base64.b64encode(public_key).decode('utf-8')
    }

    response = requests.post(url + "/activate-account", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

    return response

def read_and_sign_file(tahap : int, privkey):
    path = f"bagian-a/13523035_A_{tahap}.pdf"
    pdf = open(path, "rb").read()

    signature = sphincs.sign(pdf, privkey)
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    pdf_b64 = base64.b64encode(pdf).decode('utf-8')

    open(f"submissions/bagian-a/tahap{tahap}pdf", "w").write(pdf_b64)
    open(f"submissions/bagian-a/tahap{tahap}sign", "w").write(signature_b64)

    return pdf_b64, signature_b64

def validate_file(file_b64, signature_b64, public_key):
    pdf = base64.b64decode(file_b64)
    signature = base64.b64decode(signature_b64)

    try:
        sphincs.verify(pdf, signature, public_key)
        print("File signature is valid!")
    except Exception as e:
        print(f"File signature is INVALID. Error: {e}")
        exit()

def construct_pdf(b64_string):
    path = "submissions/test/" + random.randbytes(6).hex() + ".pdf"
    pdf = base64.b64decode(b64_string)
    open(path, "wb").write(pdf)

def update_pubkey(newpubkey):

    secret = base64.b32encode(creds["totp_secret"].encode()).decode()
    totp = pyotp.TOTP(secret)
    totp_code = totp.now()

    _, question, answer = get_math()
    payload = {
        "username": "13523035",
        "password": "rayhan",
        "totp_code": totp_code,
        "math_question": question,
        "math_answer": answer,
        "new_public_key": base64.b64encode(newpubkey).decode('utf-8')
    }

    response = requests.post(url + "/update-public-key", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

def submit_a(tahap: int, privkey):
    assert tahap == 1 or tahap == 2

    pdf, signature = read_and_sign_file(tahap, privkey)
    
    secret = base64.b32encode(creds["totp_secret"].encode()).decode()
    totp = pyotp.TOTP(secret)
    totp_code = totp.now()

    _, question, answer = get_math()
    payload = {
        "username": "13523035",
        "totp_code": totp_code,
        "math_question": question,
        "math_answer": answer,
        "signature": signature,
        "tahap": tahap,
        "file": base64.b64decode(pdf)
    }

    # Print truncated version for debugging
    debug_payload = payload.copy()
    debug_payload["file"] = pdf[:100] + "..." if len(pdf) > 100 else pdf
    debug_payload["signature"] = signature[:100] + "..." if len(signature) > 100 else signature
    print(json.dumps(debug_payload, indent=2))

    # response = requests.post(url + "/stage-a/submit", json=payload)
    # print(f"Status: {response.status_code}")
    # print(f"Response: {response.json()}")

    # return response


def get_math():
    response = requests.get(url + "/challenge-math")
    question = response.json()["question"] 
    answer = eval(question.split("||")[0])
    return response, question, answer

def get_accounts():
    response = requests.get(url + "/accounts")

    active_list = []
    for item in response.json()["accounts"]:
        if item["status"] == "active":
            active_list.append(item["username"])
            print(item["username"])
    print(f"Total: {len(active_list)}")
    return response
     
def get_stats():
    response = requests.get(url + "/stats")
    return response

def get_health():
    response = requests.get(url + "/health")
    return response

if __name__ == "__main__":

    if "INIT" in sys.argv:
        nonce = find_nonce()  # NONCE IS 952766
        public_key, private_key = generate_keys()
        validate_keys(public_key, private_key)

        open("safe/.nonce", "w").write(str(nonce))         
        open("safe/.pub", "wb").write(public_key)         
        open("safe/.priv", "wb").write(private_key)    

    try:
        nonce = int(open("safe/.nonce").read())
        public_key = open("safe/.pub", "rb").read()
        private_key = open("safe/.priv", "rb").read()
        validate_keys(public_key, private_key)

    except:
        print("Parameters not found! use INIT to generate!")
        exit()

    if "ACTIVATE" in sys.argv:
        res = activate_account(nonce, public_key)
        open("safe/activated.txt", "w").write(json.dumps(res.json(), indent=4))

    if "ACCOUNTS" in sys.argv:
        res = get_accounts()
        open("safe/accounts.txt", "w").write(json.dumps(res.json(), indent=4, sort_keys=True))

    if "STATS" in sys.argv:
        res = get_stats()

    if "HEALTH" in sys.argv:
        res = get_health()
    
    if "PDFTEST" in sys.argv:
        b64_string = open(sys.argv[2], "r").read()
        construct_pdf(b64_string)
    
    if "SIGNTEST" in sys.argv:
        pdf = open(sys.argv[2], "r").read()
        signature = open(sys.argv[3], "r").read()
        validate_file(pdf, signature, public_key)

    if "PUBKEY" in sys.argv:
        update_pubkey(public_key)
    
    if "SUBMIT" in sys.argv:
        if sys.argv[2] == "A":
            res = submit_a(int(sys.argv[3]), private_key)
        open("safe/submit_log.txt", "w").write(json.dumps(res.json(), indent=4, sort_keys=True))