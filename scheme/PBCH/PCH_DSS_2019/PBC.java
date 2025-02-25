package scheme.PBCH.PCH_DSS_2019;

import base.GroupParam.PBC.Asymmetry;
import utils.BooleanFormulaParser;
import utils.Hash;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/*
 * Fine-Grained and Controlled Rewriting in Blockchains Chameleon-Hashing Gone Attribute-Based
 * P26. 4.4 A Concrete PBCH
 */

public class PBC {
    public static class PublicParam {
        public Asymmetry GP;
        ABE.FAME.PBC.PublicParam pp_ABE;

        public PublicParam(curve.PBC curve, boolean swap_G1G2) {
            GP = new Asymmetry(curve, swap_G1G2);
            pp_ABE = new ABE.FAME.PBC.PublicParam(GP);
        }

        public PublicParam(Asymmetry GP) {
            this.GP = GP;
            pp_ABE = new ABE.FAME.PBC.PublicParam(GP);
        }
    }

    public static class MasterPublicKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey pk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
        ABE.FAME.PBC.MasterPublicKey mpk_ABE = new ABE.FAME.PBC.MasterPublicKey();
    }

    public static class MasterSecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        ABE.FAME.PBC.MasterSecretKey msk_ABE = new ABE.FAME.PBC.MasterSecretKey();
    }

    public static class SecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        ABE.FAME.PBC.SecretKey sk_ABE = new ABE.FAME.PBC.SecretKey();
    }

    public static class HashValue {
        scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue h_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
        ABE.FAME.PBC.CipherText ct_ABE = new ABE.FAME.PBC.CipherText();
        SE.AES.CipherText ct_SE = new SE.AES.CipherText();
    }

    public static class Randomness {
        scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
    }

    scheme.CH.CH_ET_BC_CDK_2017.Native CHET;
    ABE.FAME.PBC ABE;
    Random rand = new Random();

    public PBC(int k) {
        CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native(k);
        ABE = new ABE.FAME.PBC();
    }

    public void SetUp(MasterPublicKey pk_PCH, MasterSecretKey sk_PCH, PublicParam pp_PCH) {
        CHET.KeyGen(pk_PCH.pk_CHET, sk_PCH.sk_CHET);
        ABE.SetUp(pp_PCH.pp_ABE, pk_PCH.mpk_ABE, sk_PCH.msk_ABE);
    }

    public void KeyGen(SecretKey sk, PublicParam pp_PCH, MasterPublicKey pk_PCH, MasterSecretKey sk_PCH, BooleanFormulaParser.AttributeList S) {
        sk.sk_CHET = sk_PCH.sk_CHET;
        ABE.KeyGen(sk.sk_ABE, pp_PCH.pp_ABE, pk_PCH.mpk_ABE, sk_PCH.msk_ABE, S);
    }

    public void Hash(HashValue H, Randomness R, PublicParam pp_PCH, MasterPublicKey pk_PCH, base.LSSS.PBC.Matrix MSP, String m) {
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        CHET.Hash(H.h_CHET, R.r_CHET, etd, pk_PCH.pk_CHET, m);
        byte[] r = new byte[16];
        rand.nextBytes(r);
        byte[] k = new byte[16];
        rand.nextBytes(k);

        Hash.H_2_element u = new Hash.H_2_element();
        Hash.H_2_element_String_2(u, pp_PCH.GP.Zr, Arrays.toString(r), MSP.formula);

        Hash.EncText enc = new Hash.EncText();
        Hash.Encode(enc, pp_PCH.GP.GT, new Hash.PlaText(k, r));

        ABE.Encrypt(H.ct_ABE, pp_PCH.pp_ABE, pk_PCH.mpk_ABE, MSP, new ABE.FAME.PBC.PlainText(enc.K), u.u_1, u.u_2);

        SE.AES.Encrypt(H.ct_SE, new SE.AES.PlainText(etd.sk_ch_2.d.toByteArray()), k);
    }

    public boolean Check(HashValue H, Randomness R, MasterPublicKey pk_PCH, String m) {
        return CHET.Check(H.h_CHET, R.r_CHET, pk_PCH.pk_CHET, m);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam pp_PCH, MasterPublicKey pk_PCH, base.LSSS.PBC.Matrix MSP, SecretKey sk, String m, String m_p) {
        ABE.FAME.PBC.PlainText pt_ABE = new ABE.FAME.PBC.PlainText();
        ABE.Decrypt(pt_ABE, pp_PCH.pp_ABE, MSP, H.ct_ABE, sk.sk_ABE);

        Hash.PlaText pla = new Hash.PlaText();
        Hash.Decode(pla, new Hash.EncText(pt_ABE.m));

        Hash.H_2_element u = new Hash.H_2_element();
        Hash.H_2_element_String_2(u, pp_PCH.GP.Zr, Arrays.toString(pla.r), MSP.formula);

        ABE.FAME.PBC.CipherText ct_p = new ABE.FAME.PBC.CipherText();
        ABE.Encrypt(ct_p, pp_PCH.pp_ABE, pk_PCH.mpk_ABE, MSP,pt_ABE, u.u_1, u.u_2);

        if(!ct_p.isEqual(H.ct_ABE)) throw new RuntimeException("wrong abe ciphertext");
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        SE.AES.PlainText se_pt = new SE.AES.PlainText();
        SE.AES.Decrypt(se_pt, H.ct_SE, pla.k);
        etd.sk_ch_2.d = new BigInteger(se_pt.pt);

        CHET.Adapt(R_p.r_CHET, H.h_CHET, R.r_CHET, etd, pk_PCH.pk_CHET, sk.sk_CHET, m, m_p);
    }
}
