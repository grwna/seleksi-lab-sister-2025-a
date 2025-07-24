import hashlib
import base64
import pyspx.sha2_256f
import requests
import json
import sys
import pyotp
import random
import dotenv
import os

dotenv.load_dotenv()

creds = {
    "username": os.getenv('USERNAME'),
    "password": os.getenv('PASSWORD'),
    "totp_secret": os.getenv('TOTP_SECRET'),
    "pow_prefix": os.getenv('POW_PREFIX'),
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
        "username": creds["username"],
        "password": creds["password"],
        "nonce":nonce,
        "public_key": base64.b64encode(public_key).decode('utf-8')
    }

    response = requests.post(url + "/activate-account", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

    return response


def update_pubkey(newpubkey):

    secret = base64.b32encode(creds["totp_secret"].encode()).decode()
    totp = pyotp.TOTP(secret)
    totp_code = totp.now()

    _, question, answer = get_math()
    payload = {
        "username": creds["username"],
        "password": creds["password"],
        "totp_code": totp_code,
        "math_question": question,
        "math_answer": answer,
        "new_public_key": base64.b64encode(newpubkey).decode('utf-8')
    }

    response = requests.post(url + "/update-public-key", json=payload)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")


def read_and_sign_file(tahap : int, privkey):
    path = f"bagian-a/{creds['username']}_A_{tahap}.pdf"
    pdf = open(path, "rb").read()

    signature = sphincs.sign(pdf, privkey)
    signature_b64 = base64.b64encode(signature).decode('utf-8')

    open(f"submissions/bagian-a/{creds["username"]}_A_{tahap}.pdf", "wb").write(pdf)
    open(f"submissions/bagian-a/{creds["username"]}_A_{tahap}.pdf.sign", "w").write(signature_b64)

    return pdf, signature_b64


def validate_file(pdf_data, signature_b64, public_key):
    signature = base64.b64decode(signature_b64)

    try:
        if not sphincs.verify(pdf_data, signature, public_key):
            raise Exception("Signature verification failed")

        print("File signature is valid!")
        return True
    except Exception as e:
        print(f"File signature is INVALID. Error: {e}")
        exit()


def submit_a(tahap: int, privkey, pubkey):
    assert tahap == 1 or tahap == 2

    pdf, signature = read_and_sign_file(tahap, privkey)
    validate_file(pdf, signature, pubkey)
    
    secret = base64.b32encode(creds["totp_secret"].encode()).decode()
    totp = pyotp.TOTP(secret)
    totp_code = totp.now()

    _, question, answer = get_math()
    data = {
        "username": creds["username"],
        "totp_code": totp_code,
        "math_question": question,
        "math_answer": answer,
        "signature": signature,
        "tahap": tahap,
    }

    file_data = {
        'file' : (f'{creds['username']}_A_{tahap}.pdf', pdf, 'application/pdf')
    }

    debug_payload = data.copy()
    debug_payload["signature"] = signature[:100] + "..." if len(signature) > 100 else signature
    print(json.dumps(debug_payload, indent=2))

    response = requests.post(url + "/stage-a/submit", data=data, files=file_data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

    return response


def get_submissions():
    secret = base64.b32encode(creds["totp_secret"].encode()).decode()
    totp = pyotp.TOTP(secret)
    totp_code = totp.now()

    params = {
        "username": creds['username'],
        "totp_code": totp_code
    }

    response = requests.get(url + f"/user/{creds['username']}/submissions", params=params)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")


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
    
    if "SIGNTEST" in sys.argv:
        pdf = open(sys.argv[2], "rb").read()
        signature = open(sys.argv[3], "r").read()
        validate_file(pdf, signature, public_key)

    if "PUBKEY" in sys.argv:
        update_pubkey(public_key)
    
    if "SUBMIT" in sys.argv:
        if sys.argv[2] == "A":
            res = submit_a(int(sys.argv[3]), private_key, public_key)
        open("safe/submit_log.txt", "w").write(json.dumps(res.json(), indent=4, sort_keys=True))

    if "CHECKSUB" in sys.argv:
        get_submissions()