package ABE.MA_ABE;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.BooleanFormulaParser;
import utils.Func;
import utils.Hash;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/*
 * Efficient Statically-Secure Large-Universe Multi-Authority Attribute-Based Encryption
 * P8. 4.1 Construction
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class Authority {
        public MasterSecretKey msk = new MasterSecretKey();
        public PublicKey pk = new PublicKey();
        public List<String> control_attr = new ArrayList<>();
        public String theta;

        public Authority(String theta) {
            this.theta = theta;
        }
    }

    public static class PublicParam {
        public Field Zr, G, GT;
        Pairing pairing;
        Element g, egg;

        public Element pairing(Element g1, Element g2) {
            return pairing.pairing(g1, g2).getImmutable();
        }

        public Element H(String m) {
            return Hash.H_String_1_PBC_1(G, m);
        }

        public Element F(String m) {
            return Hash.H_String_1_PBC_1(G, m);
        }

        public Element GetGTElement() {
            return GT.newRandomElement().getImmutable();
        }

        public Element GetZrElement() {
            return Zr.newRandomElement().getImmutable();
        }
    }

    public static class PublicKey {
        public Element egg_alpha, g_y;
    }

    public static class PublicKeyGroup {
        List<PublicKey> PK = new ArrayList<>();
        HashMap<String, Integer> rho = new HashMap<>();

        public void AddPK(Authority Auth) {
            for(String attr : Auth.control_attr) rho.put(attr, PK.size());
            PK.add(Auth.pk);
        }
    }

    public static class SecretKeyGroup {
        List<SecretKey> SK = new ArrayList<>();
        HashMap<String, Integer> rho = new HashMap<>();

        public void AddSK(SecretKey sk) {
            rho.put(sk.u, SK.size());
            SK.add(new SecretKey(sk));
        }
    }

    public static class MasterSecretKey {
        public Element alpha, y;
    }

    public static class SecretKey {
        public Element K, K_p;
        public String GID, u;

        public SecretKey() {}

        public SecretKey(SecretKey sk) {
            K = sk.K;
            K_p = sk.K_p;
            GID = sk.GID;
            u = sk.u;
        }
    }

    public static class CipherText {
        public Element C_0;
        public Element[][] C;

        public boolean isEqual(CipherText ct) {
            if(C.length != ct.C.length) return false;
            if(C[0].length != ct.C[0].length) return false;
            for(int i = 0; i < C.length; ++i)
                for (int j = 0; j < C[0].length; ++j) if (!C[i][j].isEqual(ct.C[i][j])) return false;
            return C_0.isEqual(ct.C_0);
        }
    }

    public static class PlainText {
        public Element m;

        public PlainText(Element m) {
            this.m = m;
        }

        public boolean isEqual(PlainText PT) {
            return m.isEqual(PT.m);
        }
    }

    public void GlobalSetup(PublicParam GP, curve.PBC curve) {
        GP.pairing = Func.PairingGen(curve);
        GP.Zr = GP.pairing.getZr();
        GP.G = GP.pairing.getG1();
        GP.GT = GP.pairing.getGT();
        GP.g = GP.G.newRandomElement().getImmutable();
        GP.egg = GP.pairing(GP.g, GP.g).getImmutable();
    }

    public void AuthSetup(Authority Auth, PublicParam GP) {
        Auth.msk.alpha = GP.GetZrElement();
        Auth.msk.y = GP.GetZrElement();
        Auth.pk.egg_alpha = GP.egg.powZn(Auth.msk.alpha).getImmutable();
        Auth.pk.g_y = GP.g.powZn(Auth.msk.y).getImmutable();
    }

    public void KeyGen(Authority Auth, SecretKey SK, String u, PublicParam GP, String GID) {
        if(!Auth.control_attr.contains(u)) throw new  RuntimeException("authority not control this attr");
        Element t = GP.GetZrElement();
        SK.K_p = GP.g.powZn(t).getImmutable();
        SK.K = GP.g.powZn(Auth.msk.alpha).
        mul(GP.H(GID).powZn(Auth.msk.y)).
        mul(GP.F(u).powZn(t)).getImmutable();
        SK.GID = GID;
        SK.u = u;
    }

    public void Encrypt(CipherText CT, PublicParam GP, PublicKeyGroup PKG, base.LSSS.PBC.Matrix MSP, PlainText PT) {
        int l = MSP.M.length;
        int n = MSP.M[0].length;
        base.LSSS.PBC.Matrix.Vector v = new base.LSSS.PBC.Matrix.Vector();
        v.v = new Element[n];
        for(int i = 0;i < n;++i) v.v[i] = GP.GetZrElement();
        base.LSSS.PBC.Matrix.Vector t_x = new base.LSSS.PBC.Matrix.Vector();
        t_x.v = new Element[l];
        for(int i = 0;i < l;++i) t_x.v[i] = GP.GetZrElement();
        base.LSSS.PBC.Matrix.Vector w = new base.LSSS.PBC.Matrix.Vector();
        w.v = new Element[n];
        w.v[0] = GP.Zr.newZeroElement().getImmutable();
        for(int i = 1;i < n;++i) w.v[i] = GP.GetZrElement();
        Encrypt(CT, GP, PKG, MSP, PT, v, w, t_x);
    }

    public void Encrypt(CipherText CT, PublicParam GP, PublicKeyGroup PKG, base.LSSS.PBC.Matrix MSP, PlainText PT, base.LSSS.PBC.Matrix.Vector v, base.LSSS.PBC.Matrix.Vector w, base.LSSS.PBC.Matrix.Vector t_x) {
        int l = MSP.M.length;

        CT.C = new Element[4][l];
        CT.C_0 = PT.m.mul(GP.egg.powZn(v.v[0])).getImmutable();

        int rho_x;
        for(int i = 0;i < l;++i) {
            if(!PKG.rho.containsKey(MSP.policy[i])) throw new RuntimeException("invalid arrtibute");
            rho_x = PKG.rho.get(MSP.policy[i]);
            CT.C[0][i] = PKG.PK.get(rho_x).egg_alpha.powZn(t_x.v[i]).mul(GP.egg.powZn(MSP.Prodith(v, i))).getImmutable();
            CT.C[1][i] = GP.g.powZn(t_x.v[i].negate()).getImmutable();
            CT.C[2][i] = PKG.PK.get(rho_x).g_y.powZn(t_x.v[i]).mul(GP.g.powZn(MSP.Prodith(w, i))).getImmutable();
            CT.C[3][i] = GP.F(MSP.policy[i]).powZn(t_x.v[i]).getImmutable();
        }
    }

    public void Decrypt(PlainText PT, PublicParam GP, SecretKeyGroup SKG, base.LSSS.PBC.Matrix MSP, CipherText CT) {
        BooleanFormulaParser.AttributeList S = new BooleanFormulaParser.AttributeList();
        S.attrs.addAll(SKG.rho.keySet());
        base.LSSS.PBC.Matrix.Vector c = new base.LSSS.PBC.Matrix.Vector();
        MSP.Solve(c, S);
        Element tmp = GP.GT.newOneElement().getImmutable();
        for(int i = 0;i < MSP.policy.length;++i) {
            if(!c.v[i].isZero()) {
                int sk_id = SKG.rho.get(MSP.policy[i]);
                tmp = tmp.mul(
                        CT.C[0][i].mul(GP.pairing(SKG.SK.get(sk_id).K, CT.C[1][i]))
                                .mul(GP.pairing(GP.H(SKG.SK.get(sk_id).GID), CT.C[2][i]))
                                .mul(GP.pairing(SKG.SK.get(sk_id).K_p, CT.C[3][i]))
                                .powZn(c.v[i])
                ).getImmutable();
            }
        }
        PT.m = CT.C_0.div(tmp).getImmutable();
    }
}
