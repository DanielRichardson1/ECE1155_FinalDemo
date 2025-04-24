import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import time
import matplotlib.pyplot as plt 
import numpy as np

'''
Most of the code used in this simulation is from:
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ 
which is the documentation for the python cryptography library.
For more specific details on the functions used, please refer above. 

implements RSA key generation, signature, and key exchange algorithms parametrized with time and key size variation
implements ECC key generation, signature, and key exchange algorithms parametrized with time and the following NIST Recommended Polynomial Prime curves:
    1. P-192
    2. P-224
    3. P-256

'''

SHORT_MESSAGE = 'This is a short message to be signed'.encode('utf-8') 
LONG_MESSAGE = 'This is the longest message. the rest will be random characters. as;sldfkj a;lfj ow;j a;lkda agasdjf;\
    as jr wo;ioj a; kldnalkdj;alkfjaeiotjadkl;j a;lj;akl;asss3e90eir-ri496u089-783456 vjf[q[IJ4TQIJ;o;rg-0444556\
    [] figajq9et543469d ;kj495j; kaljdff adt4akladjf 32353456jsvbbnaarweiojqiortuwryop b;kjav; nadl;kqe jtp dr\
    aeeitqtjqee;tlkqerjtlykwejrt;l nbklnl;nkjsdfkl;gjsdl;kjtoerihywoihj84689u10-9 amz.vnz.adgaf' \
    'q[werfpqerotkjcnvwe/ceioj ;/zvnadf;vijao;aj9eqioeutopqieutoiy[aaa[qeoitqpoiruwopiuryiyo[pqiewvkbnb\
    kfgj;erjriequw;kbnthtlryhjoiertuoqij;alkfj;lkmnbn l;kjfgbl;kjo;ijtowe;ijtl;wkjfvl;ksdjgl;eirjto;isjg;sdklvmfbne;\
    li4utjwpogi45o4949n;slfkjbnl;krjt;lkjertl;kjb;siojo4ioj4;vkbl;bmnbne;ijtgo;irjto;ieijg;slknmbl;nkl;lkjeqoti9t\
    ioweu90u90653490680-697p;orjgl;kj32;lm4l;56m56kl567576kl;7j;l4932u5p4i5;lksdkgjvbnbn;9to;4i56j29o3i6ulkjbl\
    kjbjhbw;ljyt945j6wjt;kbnsl;kjrwp;oj6;5k6jwl;e45kj;wlgbnkt;le4j659545k67j690j95t94599;lk46j2904620645jw;\
    kjg;kljge9rtyj;k;nj;;jklsdgjk;lkj;j9rutyw9[pwo;45l;qwdsbnbf'.encode('utf-8')

MESSAGES = [SHORT_MESSAGE, MEDIUM_MESSAGE, LONG_MESSAGE]

def rsa_key_gen(key_len : int, iterations=10):

    '''
    Generates an RSA key pair with the given key length, returns average gen time over 10 iterations
    '''

    times = []

    for _ in range(iterations):
        start = time.perf_counter()
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_len
        )
        public = private.public_key()
        end = time.perf_counter()
        times.append(end - start)

    return private, public, np.mean(times)

def ecc_key_gen(curve, iterations=10):

    '''
    Generates an ECC key pair on the given curve, returns average gen time over 10 iterations
    '''

    times = []
    for _ in range(iterations):
        start = time.perf_counter()

        private = ec.generate_private_key(curve=curve)
        public = private.public_key()

        end = time.perf_counter()
        times.append(end - start)

    return private, public, np.mean(times)

def rsa_signature_and_verification(private, public, message, iterations=10):

    '''
    returns avg time to sign and time to verify a message using RSA keys
    '''
    times = []

    for _ in range(iterations):
        start = time.perf_counter()
        #  sign the SHA256 hash'd message 
        signature = private.sign(
            message,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        sign_time = time.perf_counter() - start

        start_verify = time.perf_counter()
        # simulate the verification - we have the public key, message, and signature (generated)
        public.verify(
            signature,
            message, 
            # these params should be consistent with how the message was signed
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        verify_time = time.perf_counter() - start_verify

        times.append([sign_time, verify_time])

    return np.mean(times, axis = 0).tolist()

def ecc_signature_and_verification(private, public, message, iterations=10):

    '''
    returns time to sign and time to verify a message using EC keys
    '''
    times = []
    for _ in range(iterations):
        start = time.perf_counter()

        signature = private.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

        sign_time = time.perf_counter() - start

        start_verify = time.perf_counter()

        public.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )

        verify_time = time.perf_counter() - start_verify

        times.append([sign_time, verify_time])

    return np.mean(times, axis = 0).tolist()


def main():

    key_lengths = [1024, 2048, 4096]
    rsa_gen_times = {}
    rsa_sign_verify_times = {}
    ecc_prime_curves = [ec.SECP192R1(), ec.SECP224R1(), ec.SECP256R1()]
    ecc_gen_times = {}
    ecc_sign_verify_times = {}



    for i in range(3):

        # generate key pair, record generation time for each key size / curve
        rsa_private, rsa_public, rsa_gen_times[str(key_lengths[i])] = rsa_key_gen(key_lengths[i])
        ecc_private, ecc_public, ecc_gen_times[str(ecc_prime_curves[i].name)] = ecc_key_gen(ecc_prime_curves[i])

        # sign and verify messages, record time
        # for message in MESSAGES:
        rsa_sign_verify_times[str(key_lengths[i])] = rsa_signature_and_verification(rsa_private, rsa_public, LONG_MESSAGE)
        ecc_sign_verify_times[str(ecc_prime_curves[i].name)] = ecc_signature_and_verification(ecc_private, ecc_public, LONG_MESSAGE)

    # Extract sign and verify times separately
    rsa_sign_times = {k: v[0] for k, v in rsa_sign_verify_times.items()}
    rsa_verify_times = {k: v[1] for k, v in rsa_sign_verify_times.items()}
    ecc_sign_times = {k: v[0] for k, v in ecc_sign_verify_times.items()}
    ecc_verify_times = {k: v[1] for k, v in ecc_sign_verify_times.items()}

    # plot the results in various figures
    fig1, (ax1, ax2) = plt.subplots(1,2, figsize=(15,10), constrained_layout=True)
    # plt.tight_layout(pad=2.5)
    fig1.suptitle('Key Generation for RSA and ECC Systems')

    # RSA key length vs gen time
    ax1.bar(rsa_gen_times.keys(), rsa_gen_times.values(), color='blue')
    ax1.set_title('RSA Key Generation Time by Key Length')
    ax1.set_xlabel('Key Length')
    ax1.set_ylabel('Avg Time (s)')

    ax2.bar(ecc_gen_times.keys(), ecc_gen_times.values(), color='red')
    ax2.set_title('ECC Key Generation Time by Curve')
    ax2.set_xlabel('Curve')
    ax2.set_ylabel('Avg Time (milliseconds)')
    # adjust the scale for better visual comparison
    ax2.set_yticklabels([f'{y*1000:.2f}' for y in ax2.get_yticks()])

    plt.savefig('gen_times.png')


    fig2, ((ax3, ax4), (ax5, ax6), (ax7, ax8)) = plt.subplots(3,2, figsize=(15,10), constrained_layout = True)
    fig2.suptitle('RSA & EC DSA Performance')

    # RSA sign times
    ax3.bar(rsa_sign_times.keys(), rsa_sign_times.values())
    ax3.set_title('RSA Signing Times')
    ax3.set_xlabel('Key Length')
    ax3.set_ylabel('Time (s)')

    # RSA Verify Times
    ax5.bar(rsa_verify_times.keys(), rsa_verify_times.values())
    ax5.set_title('RSA Verification Times')
    ax5.set_xlabel('Key Length')
    ax5.set_ylabel('Time (s)')

    # ECC Verify Times
    ax4.bar(ecc_sign_times.keys(), ecc_sign_times.values(), color='red')
    ax4.set_title('ECC Signing Times')
    ax4.set_xlabel('Curve')
    ax4.set_ylabel('Time (s)')

    # ECC Sign Times
    ax6.bar(ecc_verify_times.keys(), ecc_verify_times.values(), color='red')
    ax6.set_title('ECC Verification Times')
    ax6.set_xlabel('Curve')
    ax6.set_ylabel('Time (s)')

    # Sum verification + Signing for RSA
    bars_rsa = ax7.bar(rsa_sign_times.keys(), [(x + y) for x, y in zip(rsa_sign_times.values(), rsa_verify_times.values())])
    ax7.set_title('RSA DSA Time')
    ax7.set_xlabel('Curve')
    ax7.set_ylabel('Time (s)')    
    ax7.bar_label(bars_rsa, fmt='%.2e',padding=3)


    # Sum verification + Signing for ECC
    bars_ecc = ax8.bar(ecc_sign_times.keys(), [(x + y) for x, y in zip(ecc_sign_times.values(), ecc_verify_times.values())])
    ax8.set_title('ECC DSA Time')
    ax8.set_xlabel('Curve')
    ax8.set_ylabel('Time (s)')    
    ax8.bar_label(bars_ecc, fmt='%.2e',padding=3)

    plt.savefig('sv_times_long_msg.png')
    




if __name__ == '__main__':
    main()

