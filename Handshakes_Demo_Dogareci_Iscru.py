import time
import statistics
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import secrets
from alkindi import KEM
import platform, psutil

# EXPERIMENT: Classical vs Post-Quantum Handshake Performance

'''
We chose what to compare based on the differences of both approaches:

Classical TLS 1.3 Handshake:
┌─────────────────────────────────────────────────────────────┐
│ 1. Key Generation (ECDHE)         ← WE MEASURE THIS         │
│ 2. Public key exchange (network)  ← NOT MEASURED (network)  │
│ 3. Shared secret (ECDH math)      ← WE MEASURE THIS         │
│ 4. HKDF (key derivation)          ← SAME FOR BOTH (ignored) │
│ 5. AES-GCM (encrypt data)         ← SAME FOR BOTH (ignored) │
└─────────────────────────────────────────────────────────────┘

ML-KEM TLS Handshake:
┌─────────────────────────────────────────────────────────────┐
│ 1. Key Generation (ML-KEM)         ← WE MEASURE THIS        │
│ 2. Public key exchange (network)   ← NOT MEASURED (network) │
│ 3. Encapsulation (client)          ← WE MEASURE THIS        │
│ 4. Decapsulation (server)          ← WE MEASURE THIS        │
│ 5. HKDF (key derivation)           ← SAME FOR BOTH (ignored)│
│ 6. AES-GCM (encrypt data)          ← SAME FOR BOTH (ignored)│
└─────────────────────────────────────────────────────────────┘
'''






'''
CLASSICAL DIFFIE-HELLMAN (X25519):
┌────────────────────────────────────────────────────────────────┐
│ Client                          Server                         │
│ ──────                          ──────                         │
│ 1. Generate key pair           1. Generate key pair            │
│    (priv_C, pub_C)                 (priv_S, pub_S)             │
│                                                                │
│ 2. Send pub_C ─────────────────→                               │
│                                                                │
│ 3.                     ←───────────────── Send pub_S           │
│                                                                │
│ 4. Compute secret =             4. Compute secret =            │
│    priv_C · pub_S                  priv_S · pub_C              │
│    (same result on both sides)     (same result on both sides) │
└────────────────────────────────────────────────────────────────┘
'''

def measure_classical_handshake(iterations=100):
    # Measure X25519 performance - how long cryptographic operations take
    keygen_times = [] # store timing for key generation
    derive_times = [] # store timing for shared secret derivation
    
    for _ in range(iterations):
        # PART 1: KEY GENERATION
        # Each side (client & server) generates their own key pair
        # Private key = secret, Public key = sent over network
        start = time.perf_counter()

        client_priv = X25519PrivateKey.generate()
        client_pub = client_priv.public_key()
        server_priv = X25519PrivateKey.generate()
        server_pub = server_priv.public_key()

        keygen_time = (time.perf_counter() - start) * 1_000_000
        keygen_times.append(keygen_time)
        
        # PART 2: SHARED SECRET DERIVATION
        # After exchanging public keys, each side computes the same shared secret
        # "Diffie-Hellman" math
        start = time.perf_counter()

        # Client computes secret using his private key + server's public key
        client_shared = client_priv.exchange(server_pub)
        # Server computes secret using his private key + client's public key
        server_shared = server_priv.exchange(client_pub)
        # If correct, client_shared == server_shared
        # Session key (HKDF) will be derived from this secret later

        derive_time = (time.perf_counter() - start) * 1_000_000
        derive_times.append(derive_time)
    
    return {
        'keygen_us': statistics.mean(keygen_times),
        'keygen_std': statistics.stdev(keygen_times),
        'derive_us': statistics.mean(derive_times),
        'derive_std': statistics.stdev(derive_times),
    }



'''
ML-KEM (Key Encapsulation Mechanism):
┌─────────────────────────────────────────────────────────────────┐
│ Client                          Server                          │
│ ──────                          ──────                          │
│                                 1. Generate key pair            │
│                                    (pub_KEM, priv_KEM)          │
│                                                                 │
│ 2.                     ←───────────────── Send pub_KEM          │
│                                                                 │
│ 3. Encapsulate(pub_KEM) →                                       │
│    - creates random secret K                                    │
│    - creates ciphertext C                                       │
│                                                                 │
│ 4. Send C ──────────────────→                                   │
│                                                                 │
│                                 5. Decapsulate(C, priv_KEM)     │
│                                    - recovers secret K          │
│                                    (same as client's K)         │
└─────────────────────────────────────────────────────────────────┘
'''

def measure_mlkem_handshake(iterations=100):
    # Measure ML-KEM-768 performance - how long post-quantum crypto operations take
    # ML-KEM is a Key Encapsulation Mechanism (KEM), different from Diffie-Hellman
    keygen_times = [] # store timing for key pair generation
    encaps_times = [] # store timing for encapsulation (client creates ciphertext)
    decaps_times = [] # store timing for decapsulation (server recovers secret)
    
    for _ in range(iterations):
        # PART 1: KEY GENERATION
        # Server generates a key pair (different from classical DH)
        # - Public key (encapsulation key): can be shared publicly
        # - Private key (decapsulation key): must stay secret
        start = time.perf_counter()

        # public key size: 1184 bytes
        # private key size: 2400 bytes
        keypair = KEM.generate_keypair("ML-KEM-768")

        keygen_time = (time.perf_counter() - start) * 1_000_000
        keygen_times.append(keygen_time)
        
        # PART 2: ENCAPSULATION (Client side)
        # Client takes server's public key and "encapsulates" a shared secret
        start = time.perf_counter()

        # - ciphertext: sent to server over network (1088 bytes)
        # - shared_secret: kept by client, used for AES encryption
        ciphertext, shared_secret = KEM.encapsulate("ML-KEM-768", keypair.public_key)

        encaps_time = (time.perf_counter() - start) * 1_000_000
        encaps_times.append(encaps_time)
        
        # PART 3: DECAPSULATION (Server side)
        # Server decapsulates using private key + ciphertext from client
        # Recovers the SAME shared secret that client created
        start = time.perf_counter()

        recovered_secret = KEM.decapsulate("ML-KEM-768", keypair.private_key, ciphertext)

        decaps_time = (time.perf_counter() - start) * 1_000_000
        decaps_times.append(decaps_time)
    
        # After this, both parties have the same shared_secret
        # They will both derive the AES session key using HKDF (same as classical)
        
    return {
        'keygen_us': statistics.mean(keygen_times),
        'keygen_std': statistics.stdev(keygen_times),
        'encaps_us': statistics.mean(encaps_times),
        'encaps_std': statistics.stdev(encaps_times),
        'decaps_us': statistics.mean(decaps_times),
        'decaps_std': statistics.stdev(decaps_times),
    }



# DEMO 1: Classical TLS (Vulnerable)
print("DEMO 1: CLASSICAL TLS 1.3 (Vulnerable to Quantum Attack)")

client_priv = X25519PrivateKey.generate()
client_pub = client_priv.public_key()
server_priv = X25519PrivateKey.generate()
server_pub = server_priv.public_key()

client_shared = client_priv.exchange(server_pub)
session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"tls13").derive(client_shared)

secret_message = b"Sensitive Data: Patient medical records"
nonce = secrets.token_bytes(12)
ciphertext = AESGCM(session_key).encrypt(nonce, secret_message, b"")

print(f"\nAttacker Harvests the Following:")
print(f"  Client public key: {client_pub.public_bytes_raw().hex()}")
print(f"  Client public key length: {len(client_pub.public_bytes_raw())} bytes")
print(f"  Server public key: {server_pub.public_bytes_raw().hex()}")
print(f"  Server public key lenght: {len(server_pub.public_bytes_raw())} bytes")
print(f"  Ciphertext: {ciphertext.hex()}")
print("\nA future quantum computer can decrypt this message!")

print("\n")
print("------------------------------------------------------------------------------")
print("\n")

# DEMO 2: ML-KEM (Quantum-Resistant)
print("DEMO 2: ML-KEM POST-QUANTUM (Quantum-Resistant)")

keypair = KEM.generate_keypair("ML-KEM-768")
ciphertext_kem, shared_secret = KEM.encapsulate("ML-KEM-768", keypair.public_key)
recovered = KEM.decapsulate("ML-KEM-768", keypair.private_key, ciphertext_kem)

aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mlkem").derive(shared_secret)
nonce2 = secrets.token_bytes(12)
ciphertext_aes = AESGCM(aes_key).encrypt(nonce2, secret_message, b"")

print(f"\nAttacker Harvests the Following:")
print(f"  ML-KEM public key: {keypair.public_key.hex()}")
print(f"  ML-KEM public key length: {len(keypair.public_key)} bytes")
print(f"  KEM ciphertext: {ciphertext_kem.hex()}")
print(f"  KEM ciphertext lenght: {len(ciphertext_kem)} bytes")
print(f"  AES ciphertext: {ciphertext_aes.hex()}")
print("\nEven a future quantum computer can't decrypt this message!")

print("\n")
print("------------------------------------------------------------------------------")
print("\n")



# Measurements
print("EXPERIMENT RESULTS (100 iterations each)")

classical = measure_classical_handshake(100)
mlkem = measure_mlkem_handshake(100)

print("\n--- Key and Message Sizes ---")
print(f"  X25519 public key:           32 bytes")
print(f"  ML-KEM-768 public key:     1184 bytes")
print(f"  ML-KEM-768 ciphertext:     1088 bytes")

print("\n--- Protocol Overhead per Handshake/Handshake Size Comparison ---")
print(f"  Classical (X25519 total wire):         64 bytes")
print(f"  Post-Quantum (ML-KEM-768 total wire):  2,272 bytes")
print(f"  Overhead increase:           35.5x")

print("\n--- Computational Overhead (microseconds) - Mean ; Standard Deviation ---")
print(f"  X25519 key generation:        {classical['keygen_us']:.0f} μs ; ± {classical['keygen_std']:.0f} μs")
print(f"  X25519 secret derivation:     {classical['derive_us']:.0f} μs ; ± {classical['derive_std']:.0f} μs")
print(f"  X25519 TOTAL handshake:       {classical['keygen_us'] + classical['derive_us']:.0f} μs")
print()
print(f"  ML-KEM-768 key generation:    {mlkem['keygen_us']:.0f} μs ; ± {mlkem['keygen_std']:.0f} μs")
print(f"  ML-KEM-768 encapsulation:     {mlkem['encaps_us']:.0f} μs ; ± {mlkem['encaps_std']:.0f} μs")
print(f"  ML-KEM-768 decapsulation:     {mlkem['decaps_us']:.0f} μs ; ± {mlkem['decaps_std']:.0f} μs")
print(f"  ML-KEM-768 TOTAL handshake:   {mlkem['keygen_us'] + mlkem['encaps_us'] + mlkem['decaps_us']:.0f} μs")

print("\n--- SUMMARY ---")
print(f"  Wire size increase:           35.5x (64 bytes → 2272 bytes)")
print(f"  Speed slowdown:               {(mlkem['keygen_us'] + mlkem['encaps_us'] + mlkem['decaps_us']) / (classical['keygen_us'] + classical['derive_us']):.1f}x")
print(f"  Classical handshake:          {(classical['keygen_us'] + classical['derive_us'])/1000:.3f} ms")
print(f"  ML-KEM handshake:             {(mlkem['keygen_us'] + mlkem['encaps_us'] + mlkem['decaps_us'])/1000:.3f} ms")

print("\n")
print(f"CPU: {platform.processor()}")
print(f"RAM: {psutil.virtual_memory().total / (1024**3):.0f} GB")
print(f"OS: {platform.system()} {platform.version()}")
