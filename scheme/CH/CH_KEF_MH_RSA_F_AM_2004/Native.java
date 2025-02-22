package scheme.CH.CH_KEF_MH_RSA_F_AM_2004;

/*
 * On the Key Exposure Problem in Chameleon Hashes
 * P9. Key Exposure Freeness with Message Hiding
 */

import utils.Func;
import utils.Hash;

import java.math.BigInteger;
import java.util.Random;

public class Native {
    public static class PublicParam {
        public int tau, k;
    }

    public static class PublicKey {
        public BigInteger n, e;

        public void CopyFrom(AE.RSA.Native.PublicKey pk) {
            n = pk.N;
            e = pk.e;
        }
    }

    public static class SecretKey {
        public BigInteger p, q, d;

        public void CopyFrom(AE.RSA.Native.SecretKey sk) {
            p = sk.p;
            q = sk.q;
            d = sk.d;
        }
    }

    public static class HashValue {
        public BigInteger h;
    }

    public static class Randomness {
        public BigInteger r;
    }

    Random rand = new Random();

    private static BigInteger H(BigInteger m) {
        return Hash.H_native_1_1(m);
    }

    private BigInteger C(BigInteger m, int bit_len) {
        return H(m).mod(BigInteger.TWO.pow(bit_len));
    }

    private BigInteger H(BigInteger m, int bit_len) {
        return H(m).mod(BigInteger.TWO.pow(bit_len));
    }

    private BigInteger getHashValue(Randomness r, PublicKey pk, BigInteger m, BigInteger L, PublicParam pp) {
        return C(L, 2 * pp.k - 1).
        modPow(H(m, pp.tau), pk.n).
        multiply(r.r.modPow(pk.e, pk.n)).
        mod(pk.n);
    }

    public void SetUp(PublicParam pp, int tau, int k) {
        pp.k = k;
        pp.tau = tau;
    }

    public void KeyGen(PublicKey pk, SecretKey sk, PublicParam pp) {
        AE.RSA.Native.PublicKey rsa_pk = new AE.RSA.Native.PublicKey();
        AE.RSA.Native.SecretKey rsa_sk = new AE.RSA.Native.SecretKey();
        AE.RSA.Native.KeyGen(rsa_pk, rsa_sk, pp.tau, pp.k);
        pk.CopyFrom(rsa_pk);
        sk.CopyFrom(rsa_sk);
    }

    public void Hash(HashValue h, Randomness r, PublicKey pk, BigInteger L, BigInteger m, PublicParam pp) {
        r.r = Func.getZq(rand, pk.n);
        h.h = getHashValue(r, pk, m, L, pp);
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, BigInteger L, BigInteger m, PublicParam pp) {
        return h.h.compareTo(getHashValue(r, pk, m, L, pp)) == 0;
    }

    public void Adapt(Randomness r_p, Randomness r, PublicKey pk, SecretKey sk, BigInteger L, BigInteger m, BigInteger m_p, PublicParam pp) {
        r_p.r = r.r.
        multiply(
            c.
            modPow(sk.d, pk.n).
            modPow(hm.subtract(hmp), pk.n)
            )
        .mod(pk.n);
    }
}
