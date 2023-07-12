import random
import base64
import sys

def is_MillerRabin_prime(n: int) -> bool:
    # ignore most simple case
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # convert n-1 to "d * 2^s"
    s = 0
    d = n - 1
    while d % 2 == 0:
        d = d // 2
        s += 1

    # Performed 10 Miller-Rabinin tests
    for _ in range(10):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime_number(length: int) -> int:
    while True:
        num = random.getrandbits(length)
        num |= (1 << length - 1) | 1
        if is_MillerRabin_prime(num):
            return num

def extended_gcd_iterative(a:int, b:int) -> [int, int, int]:
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def mod_inverse_iterative(e:int, r:int) -> int:
    gcd, x, _ = extended_gcd_iterative(e, r)
    if gcd != 1:
        return -1
    else:
        return x % r

if __name__ == '__main__':
    user_name = sys.argv[1]

    p = generate_prime_number(1024)
    q = generate_prime_number(1024)
    while p == q:
        q = generate_prime_number(1024)
    pq = p * q
    r = (p - 1) * (q - 1)

    while True:
        e = random.randint(1, r - 1)
        d = mod_inverse_iterative(e, r)
        if ((e * d) % r) == 1:
            break

    pub = hex(pq) + "," + hex(e)
    prv = hex(p) + "," + hex(q) + "," + hex(d)
    pub = base64.b64encode((bytes(pub, 'utf-8'))).decode('utf-8')
    prv = base64.b64encode((bytes(prv, 'utf-8'))).decode('utf-8')
    # dump public key
    file_name = user_name + '.pub'
    file = open(file_name, 'w')
    file.write(pub)
    file.close()
    # dump secret key
    file_name = user_name + '.prv'
    file = open(file_name, 'w')
    file.write(prv)
    file.close()
