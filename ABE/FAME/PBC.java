package ABE.FAME;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.BooleanFormulaParser;
import utils.Func;
import utils.Hash;

import java.util.HashMap;

/*
 * FAME: Fast Attribute-based Message Encryption
 * P6. 3 FAME: OUR CP-ABE SCHEME
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class PublicParam {
        Pairing pairing;
        boolean swap_G1G2;
        public Field Zr, G1, G2, GT;
        public Element h, H_1, H_2, T_1, T_2;

        public Element pairing(Element g1, Element g2) {
            if(swap_G1G2) return pairing.pairing(g2, g1).getImmutable();
            else return pairing.pairing(g1, g2).getImmutable();
        }

        public Element H(String m) {
            return Hash.H_String_1_PBC_1(G1, m);
        }

        public Element GetG1Element() {
            return G1.newRandomElement().getImmutable();
        }

        public Element GetG2Element() {
            return G2.newRandomElement().getImmutable();
        }

        public Element GetGTElement() {
            return GT.newRandomElement().getImmutable();
        }

        public Element GetZrElement() {
            return Zr.newRandomElement().getImmutable();
        }
    }

    public static class MasterSecretKey {
        public Element g, h, b_1, b_2, a_1, a_2, g_d1, g_d2, g_d3;
    }

    public static class SecretKey {
        HashMap<String, Integer> Attr2id;
        BooleanFormulaParser.AttributeList S = new BooleanFormulaParser.AttributeList();
        Element[][] sk_y;
        Element[] sk_0 = new Element[3], sk_p = new Element[3];

        public void Init(BooleanFormulaParser.AttributeList S) {
            Attr2id = new HashMap<>();
            sk_y = new Element[S.attrs.size()][3];
            this.S.attrs.addAll(S.attrs);
        }
    }

    public static class CipherText {
        Element[] ct_0 = new Element[3];
        Element[][] ct;
        Element ct_p;

        public boolean isEqual(CipherText CT_p) {
            if(ct_0.length != CT_p.ct_0.length) return false;
            if(ct.length != CT_p.ct.length) return false;
            if(ct[0].length != CT_p.ct[0].length) return false;
            for(int i = 0; i < ct_0.length; ++i) {
                if(!ct_0[i].equals(CT_p.ct_0[i])) return false;
            }
            for(int i = 0; i < ct.length; ++i) {
                for(int j = 0; j < ct[i].length; ++j) {
                    if(!ct[i][j].equals(CT_p.ct[i][j])) return false;
                }
            }
            return ct_p.isEqual(CT_p.ct_p);
        }
    }

    public static class PlainText {
        public Element m;

        public PlainText() {}

        public PlainText(Element m) {
            this.m = m;
        }

        public boolean isEqual(PlainText p) {
            return m.isEqual(p.m);
        }
    }

    public void SetUp(PublicParam SP, MasterSecretKey msk, curve.PBC curve, boolean swap_G1G2) {
        SP.swap_G1G2 = swap_G1G2;
        SP.pairing = Func.PairingGen(curve);
        if(swap_G1G2) {
            SP.G1 = SP.pairing.getG2();
            SP.G2 = SP.pairing.getG1();
        } else {
            SP.G1 = SP.pairing.getG1();
            SP.G2 = SP.pairing.getG2();
        }
        SP.GT = SP.pairing.getGT();
        SP.Zr = SP.pairing.getZr();

        Element d_1 = SP.GetZrElement();
        Element d_2 = SP.GetZrElement();
        Element d_3 = SP.GetZrElement();

        SP.h = SP.GetG2Element();
        msk.h = SP.h;
        msk.g = SP.GetG1Element();
        Element egh = SP.pairing(msk.g, msk.h);

        msk.a_1 = SP.GetZrElement();
        msk.a_2 = SP.GetZrElement();
        SP.H_1 = SP.h.powZn(msk.a_1).getImmutable();
        SP.H_2 = SP.h.powZn(msk.a_2).getImmutable();
        SP.T_1 = egh.powZn(d_1.mul(msk.a_1).add(d_3)).getImmutable();
        SP.T_2 = egh.powZn(d_2.mul(msk.a_2).add(d_3)).getImmutable();

        msk.b_1 = SP.GetZrElement();
        msk.b_2 = SP.GetZrElement();
        msk.g_d1 = msk.g.powZn(d_1).getImmutable();
        msk.g_d2 = msk.g.powZn(d_2).getImmutable();
        msk.g_d3 = msk.g.powZn(d_3).getImmutable();
    }

    public void KeyGen(SecretKey sk, MasterSecretKey msk, PublicParam SP, BooleanFormulaParser.AttributeList S) {
        sk.Init(S);
        Element r_1 = SP.GetZrElement(), r_2 = SP.GetZrElement();
        sk.sk_0[0] = SP.h.powZn(msk.b_1.mul(r_1)).getImmutable();
        sk.sk_0[1] = SP.h.powZn(msk.b_2.mul(r_2)).getImmutable();
        sk.sk_0[2] = SP.h.powZn(r_1.add(r_2)).getImmutable();

        int i = 0;
        for(String y : S.attrs) {
            sk.Attr2id.put(y, i);
            Element sigma_y = SP.GetZrElement();
            sk.sk_y[i][0] = SP.H(y + "11").powZn(msk.b_1.mul(r_1).div(msk.a_1))
                    .mul(SP.H(y + "21").powZn(msk.b_2.mul(r_2).div(msk.a_1)))
                    .mul(SP.H(y + "31").powZn(r_1.add(r_2).div(msk.a_1))).mul(msk.g.powZn(sigma_y.div(msk.a_1))).getImmutable();

            sk.sk_y[i][1] = SP.H(y + "12").powZn(msk.b_1.mul(r_1).div(msk.a_2))
                    .mul(SP.H(y + "22").powZn(msk.b_2.mul(r_2).div(msk.a_2)))
                    .mul(SP.H(y + "32").powZn(r_1.add(r_2).div(msk.a_2))).mul(msk.g.powZn(sigma_y.div(msk.a_2))).getImmutable();
            sk.sk_y[i][2] = msk.g.powZn(sigma_y.negate()).getImmutable();
            ++i;
        }

        Element sigma_p = SP.GetZrElement();
        sk.sk_p[0] = msk.g_d1.mul(SP.H("0111").powZn(msk.b_1.mul(r_1).div(msk.a_1)))
                .mul(SP.H("0121").powZn(msk.b_2.mul(r_2).div(msk.a_1)))
                .mul(SP.H("0131").powZn(r_1.add(r_2).div(msk.a_1))).mul(msk.g.powZn(sigma_p.div(msk.a_1))).getImmutable();

        sk.sk_p[1] = msk.g_d2.mul(SP.H("0112").powZn(msk.b_1.mul(r_1).div(msk.a_2)))
                .mul(SP.H("0122").powZn(msk.b_2.mul(r_2).div(msk.a_2)))
                .mul(SP.H("0132").powZn(r_1.add(r_2).div(msk.a_2))).mul(msk.g.powZn(sigma_p.div(msk.a_2))).getImmutable();

        sk.sk_p[2] = msk.g_d3.mul(msk.g.powZn(sigma_p.negate())).getImmutable();
    }

    public void Encrypt(CipherText CT, PublicParam SP, base.LSSS.PBC.Matrix MSP, PlainText PT) {
        Element s_1 = SP.GetZrElement();
        Element s_2 = SP.GetZrElement();
        Encrypt(CT, SP, MSP, PT, s_1, s_2);
    }

    public void Encrypt(CipherText CT, PublicParam SP, base.LSSS.PBC.Matrix MSP, PlainText PT, Element s_1, Element s_2) {
        CT.ct_0[0] = SP.H_1.powZn(s_1).getImmutable();
        CT.ct_0[1] = SP.H_2.powZn(s_2).getImmutable();
        CT.ct_0[2] = SP.h.powZn(s_1.add(s_2)).getImmutable();

        CT.ct_p = SP.T_1.powZn(s_1).mul(SP.T_2.powZn(s_2)).mul(PT.m).getImmutable();

        int n1 = MSP.M.length, n2 = MSP.M[0].length;
        CT.ct = new Element[n1][3];
        Element tmp;
        for(int i = 0; i < n1; ++i) {
            for(int l = 1;l <= 3;++l) {
                tmp = SP.H(String.format("%s%d1", MSP.policy[i], l)).powZn(s_1).mul(SP.H(String.format("%s%d2", MSP.policy[i], l)).powZn(s_2)).getImmutable();
                for(int j = 1; j <= n2; ++j) tmp = tmp.mul(SP.H(String.format("0%d%d1", j, l)).powZn(s_1)
                        .mul(SP.H(String.format("0%d%d2", j, l)).powZn(s_2)).powZn(MSP.M[i][j - 1])).getImmutable();
                CT.ct[i][l - 1] = tmp;
            }
        }
    }

    public void Decrypt(PlainText PT, PublicParam SP, base.LSSS.PBC.Matrix MSP, CipherText CT, SecretKey sk) {
        base.LSSS.PBC.Matrix.Vector gamma = new base.LSSS.PBC.Matrix.Vector();
        MSP.Solve(gamma, sk.S);
        Element num = CT.ct_p;
        for(int t = 0;t < 3;++t) {
            Element tmp = SP.G1.newOneElement().getImmutable();
            for(int i = 0;i < CT.ct.length;++i) tmp = tmp.mul(CT.ct[i][t].powZn(gamma.v[i])).getImmutable();
            num = num.mul(SP.pairing(tmp, sk.sk_0[t]));
        }
        Element den = SP.GT.newOneElement().getImmutable();
        for(int t = 0;t < 3;++t) {
            Element tmp = sk.sk_p[t];
            for(int i = 0;i < CT.ct.length;++i) {
                if(sk.Attr2id.get(MSP.policy[i]) == null) continue;
                tmp = tmp.mul(sk.sk_y[sk.Attr2id.get(MSP.policy[i])][t].powZn(gamma.v[i])).getImmutable();
            }
            den = den.mul(SP.pairing(tmp, CT.ct_0[t]));
        }
        PT.m = num.div(den).getImmutable();
    }
}
