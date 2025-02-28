package scheme.PBCH.PCHBA_TLL_2020;

import base.GroupParam.PBC.Asymmetry;
import it.unisa.dia.gas.jpbc.Element;
import utils.BooleanFormulaParser;
import utils.Hash;

import java.util.Arrays;
import java.util.Map;
import java.util.Random;

/*
 * Policy-based Chameleon Hash for Blockchain Rewriting with Black-box Accountability
 * P8. 6.2 Instantiation
 */

public class PBC {
    public static class PublicParam {
        public Asymmetry GP;
        public ABE.FAME.PBC.PublicParam pp_FAME;
        public Random rand = new Random();

        public PublicParam(curve.PBC curve, boolean swap_G1G2) {
            GP = new Asymmetry(curve, swap_G1G2);
            pp_FAME = new ABE.FAME.PBC.PublicParam(GP);
        }

        public PublicParam(Asymmetry GP) {
            this.GP = GP;
            pp_FAME = new ABE.FAME.PBC.PublicParam(GP);
        }

        public Element H2(String m) {
            return Hash.H_String_1_PBC_1(GP.Zr, m);
        }
    }

    public static class MasterPublicKey {
        //        g1~k, galpha1~k, h1~k, galpha, hd/alpha, h1/alpha, hbeta/alpha
        public ABE.FAME.PBC.MasterPublicKey mpk_FAME = new ABE.FAME.PBC.MasterPublicKey();
        public Element g_alpha, h_d_alpha, h_1_alpha, h_beta_alpha, pk_ch;
        public Element[] g_i, g_alpha_i, h_i;
    }

    public static class MasterSecretKey {
        public ABE.FAME.PBC.MasterSecretKey msk_FAME = new ABE.FAME.PBC.MasterSecretKey();
//        alpha, beta, z1~k
        public Element alpha, beta, sk_ch;
        public Element[] z_i;
    }

    public static class SecretKey {
        public ABE.FAME.PBC.SecretKey sk_FAME = new ABE.FAME.PBC.SecretKey();
        public Element[] sk_0_g = new Element[3];
        public Element sk_1, sk_ch;
        public Element[] sk_2;

        public void CopyFrom(SecretKey sk) {
            sk_FAME.CopyFrom(sk.sk_FAME);
            sk_0_g = Arrays.copyOf(sk.sk_0_g, sk.sk_0_g.length);
            sk_2 = Arrays.copyOf(sk.sk_2, sk.sk_2.length);
            sk_1 = sk.sk_1;
            sk_ch = sk.sk_ch;
        }

        public boolean delegate(PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, Element ID_i_1, Element I_i_1) {
//            mod.ssk.sk_FAME, SP.pp_FAME, mpk.mpk_FAME, msk.msk_FAME, S, r_1, r_2, R
            if(sk_2.length == 0) return false;
            Element z_1 = SP.GP.GetZrElement();
            Element z_2 = SP.GP.GetZrElement();
            Element z = z_1.add(z_2).getImmutable();

            sk_FAME.sk_0[0] = sk_FAME.sk_0[0].mul(mpk.mpk_FAME.h.powZn(msk.msk_FAME.b_1.mul(z_1))).getImmutable();
            sk_FAME.sk_0[1] = sk_FAME.sk_0[1].mul(mpk.mpk_FAME.h.powZn(msk.msk_FAME.b_2.mul(z_2))).getImmutable();
            sk_FAME.sk_0[2] = sk_FAME.sk_0[2].mul(mpk.h_1_alpha.powZn(z)).getImmutable();
            sk_0_g[1] = sk_0_g[1].mul(sk_0_g[0].powZn(z)).getImmutable();

            Element alpha_a_1 = msk.alpha.mul(msk.msk_FAME.a_1).getImmutable();
            Element alpha_a_2 = msk.alpha.mul(msk.msk_FAME.a_2).getImmutable();

            for(Map.Entry<String, Integer> entry : sk_FAME.Attr2id.entrySet()) {
                sk_FAME.sk_y[entry.getValue()][0] = sk_FAME.sk_y[entry.getValue()][0].mul(SP.pp_FAME.H(entry.getKey() + "11").powZn(msk.msk_FAME.b_1.mul(z_1).div(msk.msk_FAME.a_1))
                        .mul(SP.pp_FAME.H(entry.getKey() + "21").powZn(msk.msk_FAME.b_2.mul(z_2).div(msk.msk_FAME.a_1)))
                        .mul(SP.pp_FAME.H(entry.getKey() + "31").powZn(z.div(alpha_a_1))));

                sk_FAME.sk_y[entry.getValue()][1] = sk_FAME.sk_y[entry.getValue()][1].mul(SP.pp_FAME.H(entry.getKey() + "12").powZn(msk.msk_FAME.b_1.mul(z_1).div(msk.msk_FAME.a_2))
                        .mul(SP.pp_FAME.H(entry.getKey() + "22").powZn(msk.msk_FAME.b_2.mul(z_2).div(msk.msk_FAME.a_2)))
                        .mul(SP.pp_FAME.H(entry.getKey() + "32").powZn(z.div(alpha_a_2))));
            }
            sk_FAME.sk_p[0] = sk_FAME.sk_p[0].mul(SP.pp_FAME.H("0111").powZn(msk.msk_FAME.b_1.mul(z_1).div(msk.msk_FAME.a_1))
                    .mul(SP.pp_FAME.H("0121").powZn(msk.msk_FAME.b_2.mul(z_2).div(msk.msk_FAME.a_1)))
                    .mul(SP.pp_FAME.H("0131").powZn(z.div(alpha_a_1))));

            sk_FAME.sk_p[1] = sk_FAME.sk_p[1].mul(SP.pp_FAME.H("0112").powZn(msk.msk_FAME.b_1.mul(z_1).div(msk.msk_FAME.a_2))
                    .mul(SP.pp_FAME.H("0122").powZn(msk.msk_FAME.b_2.mul(z_2).div(msk.msk_FAME.a_2)))
                    .mul(SP.pp_FAME.H("0132").powZn(z.div(alpha_a_2))));

            sk_1 = sk_1.mul(sk_2[0].powZn(I_i_1)).mul(ID_i_1.powZn(z)).getImmutable();
            sk_2 = Arrays.copyOfRange(sk_2, 1, sk_2.length);
            for(int i = 0;i < sk_2.length;++i) sk_2[i] = sk_2[i].mul(mpk.g_alpha_i[sk_2.length - i - 1].powZn(z)).getImmutable();

            return true;
        }
    }

    public static class HashValue {
        Element b, h_p;
        Element[] owner_ID;
    }

    public static class Randomness {
        public ABE.FAME.PBC.CipherText ct_FAME = new ABE.FAME.PBC.CipherText();
        Element epk, p, sigma, c, ct_0_4, ct_1, ct_2, ct_3;
        byte[] ct, ct_p;
    }

    public static class User {
        private final SecretKey ssk = new SecretKey();
        private Element ID_hat_alpha;
        public Element ID_hat, ID_hat_h;
        public Element[] ID;

        public User(PublicParam SP, int len) {
            ID = new Element[len];
            for (int i = 0; i < len; ++i) ID[i] = SP.GP.GetZrElement();
        }

        public User(User f, PublicParam SP, int len) {
            ID = new Element[len];
            System.arraycopy(f.ID, 0, ID, 0, f.ID.length);
            for (int i = f.ID.length; i < len; ++i) ID[i] = SP.GP.GetZrElement();
        }

        public User(User u) {
            ssk.CopyFrom(u.ssk);
            ID_hat_alpha = u.ID_hat_alpha;
            ID_hat = u.ID_hat;
            ID_hat_h = u.ID_hat_h;
            ID = Arrays.copyOf(u.ID, u.ID.length);
        }

        public boolean delegate(PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, Element I_i_1) {
            ID = Arrays.copyOf(ID, ID.length + 1);
            ID[ID.length - 1] = I_i_1;
            ID_hat = ID_hat.mul(mpk.g_i[mpk.g_i.length - ID.length].powZn(I_i_1)).getImmutable();
            ID_hat_h = ID_hat_h.mul(mpk.h_i[mpk.h_i.length - ID.length].powZn(I_i_1)).getImmutable();
            ID_hat_alpha = ID_hat_alpha.mul(mpk.h_i[mpk.h_i.length - ID.length].powZn(I_i_1.mul(msk.alpha))).getImmutable();
            return ssk.delegate(SP, mpk, msk, ID_hat.powZn(msk.alpha), I_i_1);
        }
    }

    ABE.FAME.PBC FAME = new ABE.FAME.PBC();

    public void SetUp(MasterPublicKey mpk, MasterSecretKey msk, PublicParam SP, int k) {
        Element d_1 = SP.GP.GetZrElement();
        Element d_2 = SP.GP.GetZrElement();
        Element d_3 = SP.GP.GetZrElement();

        msk.alpha = SP.GP.GetZrElement();
        msk.beta = SP.GP.GetZrElement();
        msk.z_i = new Element[k];

        for(int i = 0; i < k; ++i) msk.z_i[i] = SP.GP.GetZrElement();
        FAME.SetUp(mpk.mpk_FAME, msk.msk_FAME, SP.pp_FAME, d_1, d_2, d_3, msk.alpha);
        mpk.g_i = new Element[k];
        for(int i = 0; i < k; ++i) mpk.g_i[i] = mpk.mpk_FAME.g.powZn(msk.z_i[i]).getImmutable();
        mpk.g_alpha_i = new Element[k];
        for(int i = 0; i < k; ++i) mpk.g_alpha_i[i] = mpk.g_i[i].powZn(msk.alpha).getImmutable();
        mpk.h_i = new Element[k];
        for(int i = 0; i < k; ++i) mpk.h_i[i] = mpk.mpk_FAME.h.powZn(msk.z_i[i]).getImmutable();

        mpk.g_alpha = mpk.mpk_FAME.g.powZn(msk.alpha).getImmutable();
        mpk.h_d_alpha = mpk.mpk_FAME.h.powZn(d_1.add(d_2).add(d_3).div(msk.alpha)).getImmutable();
        mpk.h_1_alpha = mpk.mpk_FAME.h.powZn(msk.alpha.invert()).getImmutable();
        mpk.h_beta_alpha = mpk.mpk_FAME.h.powZn(msk.beta.div(msk.alpha)).getImmutable();

        msk.sk_ch = SP.GP.GetZrElement();
        mpk.pk_ch = mpk.mpk_FAME.h.powZn(msk.sk_ch).getImmutable();
    }

    public void AssignUser(User usr, MasterPublicKey mpk, MasterSecretKey msk) {
        usr.ID_hat = mpk.mpk_FAME.g;
        usr.ID_hat_h = mpk.mpk_FAME.h;
        for(int i = 0;i < usr.ID.length;++i) {
            usr.ID_hat = usr.ID_hat.mul(mpk.g_i[mpk.g_i.length - i - 1].powZn(usr.ID[i])).getImmutable();
            usr.ID_hat_h = usr.ID_hat_h.mul(mpk.h_i[mpk.g_i.length - i - 1].powZn(usr.ID[i])).getImmutable();
        }
        usr.ID_hat_alpha = usr.ID_hat_h.powZn(msk.alpha).getImmutable();
    }

    public void KeyGen(User mod, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, BooleanFormulaParser.AttributeList S) {
        Element r_1 = SP.GP.GetZrElement();
        Element r_2 = SP.GP.GetZrElement();
        Element r = r_1.add(r_2).getImmutable();
        Element R = SP.GP.GetZrElement();
        FAME.KeyGen(mod.ssk.sk_FAME, SP.pp_FAME, mpk.mpk_FAME, msk.msk_FAME, S, r_1, r_2, msk.alpha);
        mod.ssk.sk_FAME.sk_0[2] = mpk.mpk_FAME.h.powZn(r.div(msk.alpha)).getImmutable();
        mod.ssk.sk_0_g[0] = mpk.mpk_FAME.g.powZn(msk.alpha.invert()).getImmutable();
        mod.ssk.sk_0_g[1] = mpk.mpk_FAME.g.powZn(r.div(msk.alpha)).getImmutable();
        mod.ssk.sk_0_g[2] = mpk.mpk_FAME.g.powZn(R).getImmutable();

        mod.ssk.sk_1 = msk.msk_FAME.g_d1.mul(msk.msk_FAME.g_d2).mul(msk.msk_FAME.g_d3).mul(mod.ID_hat.powZn(msk.alpha.mul(r))).mul(mpk.mpk_FAME.g.powZn(msk.beta.mul(R))).getImmutable();
        r = r.mul(msk.alpha).getImmutable();
        mod.ssk.sk_2 = new Element[mpk.g_i.length - mod.ID.length];
        for(int i = 0;i < mod.ssk.sk_2.length;++i) mod.ssk.sk_2[i] = mpk.g_i[mod.ssk.sk_2.length - i - 1].powZn(r).getImmutable();
        mod.ssk.sk_ch = msk.sk_ch;
    }

    private void GenCipher(Randomness R, PublicParam SP, MasterPublicKey mpk, User owner, base.LSSS.PBC.Matrix MSP, Element r, byte[] R_) {
        Element s_1 = SP.GP.GetZrElement();
        Element s_2 = SP.GP.GetZrElement();
        Element s = s_1.add(s_2).getImmutable();
        R.p = mpk.pk_ch.powZn(r).getImmutable();

        FAME.Encrypt(R.ct_FAME, SP.pp_FAME, mpk.mpk_FAME, MSP, new ABE.FAME.PBC.PlainText(SP.GP.GT.newOneElement().getImmutable()), s_1, s_2);
        R.ct_FAME.ct_0[2] = mpk.h_1_alpha.powZn(s).getImmutable();
        R.ct_0_4 = mpk.h_beta_alpha.powZn(s).getImmutable();

        R.ct = R.ct_FAME.ct_p.toBytes();
        R.ct_FAME.ct_p = SP.GP.GT.newOneElement().getImmutable();
        byte[] tmp = r.toBytes();
        for(int i = 0;i < tmp.length;++i) R.ct[i] ^= tmp[i];


        R.ct_p = SP.H2(SP.GP.pairing(mpk.mpk_FAME.g, mpk.h_d_alpha).powZn(s).toString()).toBytes();
        for(int i = 0;i < R_.length;++i) R.ct_p[i] ^= R_[i];

        R.ct_1 = owner.ID_hat_alpha.powZn(s).getImmutable();
        R.ct_2 = owner.ID_hat_h.powZn(s).getImmutable();
        R.ct_3 = R.ct_1.powZn(s).getImmutable();

        Element esk = SP.GP.GetZrElement();
        R.epk = mpk.mpk_FAME.g.powZn(esk).getImmutable();
        R_ = Arrays.copyOf(R_, SP.GP.Zr.getLengthInBytes());
        R.c = mpk.mpk_FAME.h.powZn(s.add(SP.H2(Arrays.toString(R_))));
        R.sigma = esk.add(s.mul(SP.H2(String.format("%s|%s", R.epk, R.c)))).getImmutable();
    }

    public void Hash(HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, User owner, base.LSSS.PBC.Matrix MSP, Element m) {
        H.owner_ID = Arrays.copyOf(owner.ID, owner.ID.length);

        Element r = SP.GP.GetZrElement();

        byte[] R_ = new byte[SP.GP.Zr.getLengthInBytes() / 2];
        SP.rand.nextBytes(R_);

        GenCipher(R, SP, mpk, owner, MSP, r, R_);

        H.h_p = mpk.mpk_FAME.h.powZn(SP.H2(Arrays.toString(R_))).getImmutable();

        H.b = R.p.mul(H.h_p.powZn(m)).getImmutable();
    }

    public boolean Check(HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, Element m) {
        return H.b.isEqual(R.p.mul(H.h_p.powZn(m))) &&
                SP.GP.pairing(mpk.g_alpha, R.ct_2).powZn(R.sigma).isEqual(SP.GP.pairing(R.epk, R.ct_1).mul(SP.GP.pairing(mpk.mpk_FAME.g, R.ct_3).powZn(SP.H2(R.epk + "|" + R.c))));
    }

    public void Adapt(Randomness R_p, HashValue H, Randomness R, PublicParam SP, MasterPublicKey mpk, MasterSecretKey msk, User moder, base.LSSS.PBC.Matrix MSP, Element m, Element m_p) {
        User moder_p = new User(moder);

        for(int i = moder_p.ID.length;i < H.owner_ID.length;++i)
            if(!moder_p.delegate(SP, mpk, msk, H.owner_ID[i])) throw new RuntimeException("delegate failed");

        byte[] R_ = SP.H2(SP.GP.pairing(moder_p.ssk.sk_1, R.ct_FAME.ct_0[2]).div(SP.GP.pairing(moder_p.ssk.sk_0_g[1], R.ct_1).mul(SP.GP.pairing(moder_p.ssk.sk_0_g[2], R.ct_0_4))).toString()).toBytes();
        for(int i = 0;i < R_.length;++i) R_[i] ^= R.ct_p[i];

        boolean tag = true;
        for(int i = R_.length / 2;i < R_.length;++i) if(R_[i] != 0) {
            tag = false;
            break;
        }
        if(!tag) throw new RuntimeException("unable to adapt");

        R_ = Arrays.copyOf(R_, R_.length / 2);

        ABE.FAME.PBC.PlainText pt_RABE = new ABE.FAME.PBC.PlainText();
        FAME.Decrypt(pt_RABE, SP.pp_FAME, MSP, R.ct_FAME, moder_p.ssk.sk_FAME);

        byte[] r_ = pt_RABE.m.invert().toBytes();
        for(int i = 0;i < r_.length;++i) r_[i] ^= R.ct[i];
        Element r_p = SP.GP.Zr.newElementFromBytes(r_).add(m.sub(m_p).mul(SP.H2(Arrays.toString(R_)).div(moder_p.ssk.sk_ch))).getImmutable();
        GenCipher(R_p, SP, mpk, moder_p, MSP, r_p, R_);
    }
}
