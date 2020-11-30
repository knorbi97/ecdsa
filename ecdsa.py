import secrets
import hashlib
import math

def ExtendedGCD(a, b):
  prevX, x = 1, 0
  prevY, y = 0, 1
  while b:
    q = a // b
    x, prevX = prevX - q * x, x
    y, prevY = prevY - q * y, y
    a, b = b, a % b
  return (a, prevX, prevY)

def ModularInverse(a, m):
  a, x, y = ExtendedGCD(a, m)
  return x % m

class Point:
  def __init__(self, x = 0, y = 0, z = 0):
    self.x = x
    self.y = y
    self.z = z

  def __str__(self):
    return f"({hex(self.x)}, {hex(self.y)})"

class Signature:
    def __init__(self, r, s):
      self.r = r
      self.s = s

    def __str__(self):
      return f"({self.r}, {self.s})"

class Curve:
  def __init__(self, p, a, b, G, n, h):
# Finitie field F_p
    self.p = p
# Curve paramters for E: y^2 = x^3 + ax + b over F_p
    self.a = a
    self.b = b
# Base point uncompressed G (Point => (x, y))
    self.G = G
# Order of G n
    self.n = n
# Cofactor h
    self.h = h

  def ToJacobian(self, p):
    return Point(p.x, p.y, 1)

  def ToAffine(self, p):
    z = ModularInverse(p.z, self.p)
    return Point((p.x * z ** 2) % self.p, (p.y * z ** 3) % self.p)

  def Addition(self, p, q):
    if not p.y:
      return q
    if not q.y:
      return p
    u1 = (p.x * q.z ** 2) % self.p
    u2 = (q.x * p.z ** 2) % self.p
    s1 = (p.y * q.z ** 3) % self.p
    s2 = (q.y * p.z ** 3) % self.p
    if u1 == u2:
      if s1 != s2:
        return Point(0, 0, 1)
      return self.Double(p)
    h = u2 - u1
    r = s2 - s1
    h2 = (h * h) % self.p
    h3 = (h * h2) % self.p
    u1h2 = (u1 * h2) % self.p
    nx = (r ** 2 - h3 - 2 * u1h2) % self.p
    ny = (r * (u1h2 - nx) - s1 * h3) % self.p
    nz = (h * p.z * q.z) % self.p
    return Point(nx, ny, nz)

  def Double(self, p):
    if not p.y:
      return Point(0, 0, 0)
    ysq = (p.y ** 2) % self.p
    s = (4 * p.x * ysq) % self.p
    m = (3 * p.x ** 2 + self.a * p.z ** 4) % self.p
    nx = (m ** 2 - 2 * s) % self.p
    ny = (m * (s - nx) - 8 * ysq ** 2) % self.p
    nz = (2 * p.y * p.z) % self.p
    return Point(nx, ny, nz)

  def Multiplication(self, p, scalar):
    if p.y == 0 or scalar == 0:
      return Point(0, 0, 1)
    if scalar == 1:
      return p
    if scalar < 0 or scalar >= self.n:
      return self.Multiplication(p, scalar % self.n)
    if  (scalar & 1) == 0:
      return self.Double(self.Multiplication(p, scalar // 2))
    return self.Addition(self.Double(self.Multiplication(p, scalar // 2)), p)

  def Add(self, p, q):
    return self.ToAffine(self.Addition(self.ToJacobian(p), self.ToJacobian(q)))

  def Mul(self, p, scalar):
    return self.ToAffine(self.Multiplication(self.ToJacobian(p), scalar))

class ECDSA:
  def __init__(self, curve):
    self.curve = curve

  def GenerateKeyPair(self):
    sk = secrets.randbelow(self.curve.n - 1) + 1
    pk = self.curve.Mul(self.curve.G, sk)
    return (sk, pk)

  def Sign(self, sk, m):
    hash = hashlib.sha256(m.encode("UTF8")).hexdigest()
    z = int(hash, 16)
    r, s, p = 0, 0, None
    while r == 0 or s == 0:
      k = secrets.randbelow(self.curve.n - 1) + 1
      p = self.curve.Mul(self.curve.G, k)
      r = p.x % self.curve.n
      s = ((z + r * sk) * ModularInverse(k, self.curve.n)) % self.curve.n
    return Signature(r, s)

  def Verify(self, pk, sign, m):
    hash = hashlib.sha256(m.encode("UTF8")).hexdigest()
    z = int(hash, 16)
    r = sign.r
    s = sign.s
    sInv = ModularInverse(s, self.curve.n)
    u1 = (z * sInv) % self.curve.n
    u2 = (r * sInv) % self.curve.n
    p = self.curve.Add(
      self.curve.Mul(self.curve.G, u1),
      self.curve.Mul(pk, u2)
    )
    return r == p.x
    
def main():
  # secp256k1
  ecdsa = ECDSA(Curve(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x0000000000000000000000000000000000000000000000000000000000000007,
    Point(
      0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    ),
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    0x01
  ))
  keypair = ecdsa.GenerateKeyPair()
  sk = keypair[0]
  pk = keypair[1]
  message = "Hello ECDSA!"
  signature = ecdsa.Sign(sk, message)
  print(f"Secret key: {hex(sk)}")
  print(f"Public key: {pk}")
  print(ecdsa.Verify(pk, signature, message))
  print(ecdsa.Verify(pk, signature, "Hello World!"))

if __name__ == "__main__":
  main()
