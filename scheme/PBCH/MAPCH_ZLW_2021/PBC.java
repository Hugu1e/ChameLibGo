package scheme.PBCH.MAPCH_ZLW_2021;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

import java.math.BigInteger;

/*
 * Redactable Transactions in Consortium Blockchain Controlled by Multi-authority CP-ABE
 * P11. 3.2 Generic Construction and Security Analysis
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        public ABE.MA_ABE.PBC.PublicParam GP = new ABE.MA_ABE.PBC.PublicParam();
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey hk = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey tk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
    }

    public static class Authority {
        private final MasterSecretKey mtk = new MasterSecretKey();
        public PublicKey mhk = new PublicKey();
        public ABE.MA_ABE.PBC.Authority MA_ABE_Auth;

        public Authority(String theta, PublicParam SP) {
            mtk.tk = SP.tk;
            mhk.GP = SP.GP;
            mhk.hk = SP.hk;
            MA_ABE_Auth = new ABE.MA_ABE.PBC.Authority(theta);
        }
    }

    public static class PublicKey {
        ABE.MA_ABE.PBC.PublicParam GP = new ABE.MA_ABE.PBC.PublicParam();
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey hk = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
    }

    public static class MasterSecretKey {
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey tk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
    }

    public static class SecretKey {
        ABE.MA_ABE.PBC.SecretKey MA_ABE_SK = new ABE.MA_ABE.PBC.SecretKey();
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey tk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();
    }

    public static class PublicKeyGroup {
        ABE.MA_ABE.PBC.PublicKeyGroup MA_ABE_PKG = new ABE.MA_ABE.PBC.PublicKeyGroup();
        scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey hk = new scheme.CH.CH_ET_BC_CDK_2017.Native.PublicKey();
        ABE.MA_ABE.PBC.PublicParam GP = new ABE.MA_ABE.PBC.PublicParam();

        public void AddPK(Authority Auth) {
            hk = Auth.mhk.hk;
            GP = Auth.mhk.GP;
            MA_ABE_PKG.AddPK(Auth.MA_ABE_Auth);
        }
    }

    public static class SecretKeyGroup {
        ABE.MA_ABE.PBC.SecretKeyGroup MA_ABE_SKG = new ABE.MA_ABE.PBC.SecretKeyGroup();
        scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey tk = new scheme.CH.CH_ET_BC_CDK_2017.Native.SecretKey();

        public void AddSK(SecretKey SK) {
            MA_ABE_SKG.AddSK(SK.MA_ABE_SK);
            tk = SK.tk;
        }
    }

    public static class HashValue {
        scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue CHET_H = new scheme.CH.CH_ET_BC_CDK_2017.Native.HashValue();
        ABE.MA_ABE.PBC.CipherText MA_ABE_C = new ABE.MA_ABE.PBC.CipherText();
    }

    public static class Randomness {
        scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness CHET_R = new scheme.CH.CH_ET_BC_CDK_2017.Native.Randomness();
    }

    scheme.CH.CH_ET_BC_CDK_2017.Native CHET;
    ABE.MA_ABE.PBC MA_ABE = new ABE.MA_ABE.PBC();

    private Element BigInteger2G(Field G, BigInteger m) {
        byte[] tmp = new byte[m.toByteArray().length + 2];
        tmp[1] = (byte) m.toByteArray().length;
        System.arraycopy(m.toByteArray(), 0, tmp, 2, m.toByteArray().length);
        return G.newElementFromBytes(tmp);
    }

    private BigInteger G2BigInteger(Element t) {
        byte[] tmp = t.toBytes();
        int l = tmp[1];
        if(l <= 0 || l + 2 >= tmp.length) throw new RuntimeException("decode error");
        return new BigInteger(tmp, 2, l);
    }

    public PBC(int lambda) {
        CHET = new scheme.CH.CH_ET_BC_CDK_2017.Native(lambda);
    }

    public void SetUp(PublicParam SP, curve.PBC curve) {
        MA_ABE.GlobalSetup(SP.GP, curve);
        CHET.KeyGen(SP.hk, SP.tk);
    }

    public void AuthSetup(Authority Auth) {
        MA_ABE.AuthSetup(Auth.MA_ABE_Auth, Auth.mhk.GP);
    }

    public void KeyGen(Authority Auth, SecretKey msk_i, String GID, String i) {
        MA_ABE.KeyGen(Auth.MA_ABE_Auth, msk_i.MA_ABE_SK, i, Auth.mhk.GP, GID);
        msk_i.tk = Auth.mtk.tk;
    }

    public void Hash(HashValue H, Randomness R, PublicKeyGroup MHKS, base.LSSS.PBC.Matrix MSP, BigInteger m) {
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        CHET.Hash(H.CHET_H, R.CHET_R, etd, MHKS.hk, m);
        ABE.MA_ABE.PBC.PlainText MA_ABE_PT = new ABE.MA_ABE.PBC.PlainText(BigInteger2G(MHKS.GP.GT, etd.sk_ch_2.d).getImmutable());
        MA_ABE.Encrypt(H.MA_ABE_C, MHKS.GP, MHKS.MA_ABE_PKG, MSP, MA_ABE_PT);
    }

    public boolean Check(HashValue H, Randomness R, PublicKeyGroup MHKS, BigInteger m) {
        return CHET.Check(H.CHET_H, R.CHET_R, MHKS.hk, m);
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicKeyGroup MHKS, SecretKeyGroup MSKS, base.LSSS.PBC.Matrix MSP, BigInteger m, BigInteger m_p) {
        if(!Check(H, R, MHKS, m)) throw new RuntimeException("Wrong Hash Value");
        ABE.MA_ABE.PBC.PlainText MA_ABE_PT = new ABE.MA_ABE.PBC.PlainText(MHKS.GP.GetGTElement());
        MA_ABE.Decrypt(MA_ABE_PT, MHKS.GP, MSKS.MA_ABE_SKG, MSP, H.MA_ABE_C);
        scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor etd = new scheme.CH.CH_ET_BC_CDK_2017.Native.ETrapdoor();
        etd.sk_ch_2.d = G2BigInteger(MA_ABE_PT.m);
        CHET.Adapt(R_p.CHET_R, H.CHET_H, R.CHET_R, etd, MHKS.hk, MSKS.tk, m, m_p);
    }
}
