package scheme.PBCH.RPCH_XNM_2021;

import base.GroupParam.PBC.Asymmetry;
import it.unisa.dia.gas.jpbc.Element;
import utils.BooleanFormulaParser;
import utils.Hash;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/*
 * Revocable Policy-Based Chameleon Hash
 * P13. 5.2 Proposed RPCH
 */

public class PBC {
    public static class PublicParam {
        public ABE.RABE.PBC.PublicParam SP_RABE;
        public Asymmetry GP;

        public PublicParam(curve.PBC curve, boolean swap_G1G2) {
            GP = new Asymmetry(curve, swap_G1G2);
            SP_RABE = new ABE.RABE.PBC.PublicParam(ABE.RABE.PBC.TYPE.XNM_2021, GP);
        }

        public PublicParam(Asymmetry GP) {
            this.GP = GP;
            SP_RABE = new ABE.RABE.PBC.PublicParam(ABE.RABE.PBC.TYPE.XNM_2021, GP);
        }

        public Element H(String m) {
            return SP_RABE.H(m);
        }
    }

    public static class MasterPublicKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey pk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
        public ABE.RABE.PBC.MasterPublicKey mpk_RABE = new ABE.RABE.PBC.MasterPublicKey();
    }

    public static class MasterSecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        public ABE.RABE.PBC.MasterSecretKey msk_RABE = new ABE.RABE.PBC.MasterSecretKey();
    }

    public static class SecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        public ABE.RABE.PBC.SecretKey sk_RABE = new ABE.RABE.PBC.SecretKey();
    }

    public static class UpdateKey {
        public ABE.RABE.PBC.UpdateKey ku_RABE = new ABE.RABE.PBC.UpdateKey();
    }

    public static class DecryptKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey sk_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
        public ABE.RABE.PBC.DecryptKey dk_RABE = new ABE.RABE.PBC.DecryptKey();
    }

    public static class HashValue {
        scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue h_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
        ABE.RABE.PBC.CipherText ct_RABE = new ABE.RABE.PBC.CipherText();
        SE.AES.CipherText ct_SE = new SE.AES.CipherText();
    }

    public static class Randomness {
        scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness r_CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
    }

    ABE.RABE.PBC RABE;
    scheme.CH.CH_ET_BC_CDK_2017.Native CHET;
    Random rand = new Random();

    public PBC(int k) {
        CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native(k);
        RABE = new ABE.RABE.PBC();
    }

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk, PublicParam SP) {
        CHET.KeyGen(mpk.pk_CHET, msk.sk_CHET);
        RABE.SetUp(mpk.mpk_RABE, msk.msk_RABE, SP.SP_RABE);
    }

    public void KeyGen(SecretKey sk, base.BinaryTree.PBC st, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S, Element id) {
        RABE.KeyGen(sk.sk_RABE, st, SP.SP_RABE, mpk.mpk_RABE, msk.msk_RABE, S, id);
        sk.sk_CHET.CopyFrom(msk.sk_CHET);
    }

    public void UpdateKeyGen(UpdateKey ku, PublicParam SP, MasterPublicKey mpk, base.BinaryTree.PBC st, base.BinaryTree.PBC.RevokeList rl, int t) {
        RABE.UpdateKeyGen(ku.ku_RABE, SP.SP_RABE, mpk.mpk_RABE, st, rl, t);
    }

    public void DecryptKeyGen(DecryptKey dk, PublicParam SP, MasterPublicKey mpk, SecretKey sk, UpdateKey ku, base.BinaryTree.PBC st, base.BinaryTree.PBC.RevokeList rl) {
        RABE.DecryptKeyGen(dk.dk_RABE, SP.SP_RABE, mpk.mpk_RABE, sk.sk_RABE, ku.ku_RABE, st, rl);
        dk.sk_CHET.CopyFrom(sk.sk_CHET);
    }

    public void Revoke(base.BinaryTree.PBC.RevokeList rl, Element id, int t) {
        RABE.Revoke(rl, id, t);
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, base.LSSS.PBC.Matrix MSP, String m, int t) {
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        CHET.Hash(H.h_CHET, R.r_CHET, etd, mpk.pk_CHET, m);
        byte[] r = new byte[16];
        rand.nextBytes(r);
        byte[] k = new byte[16];
        rand.nextBytes(k);
        Hash.EncText enc = new Hash.EncText();
        Hash.Encode(enc, SP.GP.GT, new Hash.PlaText(k, r));

        Hash.H_2_element u = new Hash.H_2_element();
        Hash.H_2_element_String_3(u, SP.GP.Zr, Arrays.toString(r), MSP.formula, String.valueOf(t));
        RABE.Encrypt(H.ct_RABE, SP.SP_RABE, mpk.mpk_RABE, MSP, new ABE.RABE.PBC.PlainText(enc.K), t, u.u_1, u.u_2);

        SE.AES.Encrypt(H.ct_SE, new SE.AES.PlainText(etd.sk_ch_2.d.toByteArray()), k);
    }

    public boolean Check(HashValue H, Randomness R, MasterPublicKey mpk, String m) {
        return CHET.Check(H.h_CHET, R.r_CHET, mpk.pk_CHET, m);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, DecryptKey dk, base.LSSS.PBC.Matrix MSP, String m, String m_p) {
        if(!Check(H, R, mpk, m)) throw new RuntimeException("wrong hash");
        ABE.RABE.PBC.PlainText pt_RABE = new ABE.RABE.PBC.PlainText();
        RABE.Decrypt(pt_RABE, SP.SP_RABE, dk.dk_RABE, MSP, H.ct_RABE);

        Hash.PlaText pla = new Hash.PlaText();
        Hash.Decode(pla, new Hash.EncText(pt_RABE.m));

        Hash.H_2_element u = new Hash.H_2_element();
        Hash.H_2_element_String_3(u, SP.GP.Zr, Arrays.toString(pla.r), MSP.formula, String.valueOf(dk.dk_RABE.t));

        ABE.RABE.PBC.CipherText ct_RABE = new ABE.RABE.PBC.CipherText();
        RABE.Encrypt(ct_RABE, SP.SP_RABE, mpk.mpk_RABE, MSP, pt_RABE, dk.dk_RABE.t, u.u_1, u.u_2);

        if(!ct_RABE.isEqual(H.ct_RABE)) throw new RuntimeException("wrong rabe ciphertext");

        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        SE.AES.PlainText se_pt = new SE.AES.PlainText();
        SE.AES.Decrypt(se_pt, H.ct_SE, pla.k);
        etd.sk_ch_2.d = new BigInteger(se_pt.pt);

        CHET.Adapt(R_p.r_CHET, H.h_CHET, R.r_CHET, etd, mpk.pk_CHET, dk.sk_CHET, m, m_p);
    }
}
