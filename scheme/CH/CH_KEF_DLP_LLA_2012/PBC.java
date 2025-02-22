package scheme.CH.CH_KEF_DLP_LLA_2012;

import curve.Group;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.Func;
import utils.Hash;

import java.util.HashMap;
import java.util.Map;

/*
 * Key exposure free chameleon hash schemes based on discrete logarithm problem
 * P4. CH_inf: a key exposure free chameleon hash scheme
 */

@SuppressWarnings("rawtypes")
public class PBC {
    public static class Label {
        public Element L, R;
    }

    public static class LabelGen {
        public Element y_1, omega_1;
    }

    public static class LabelManager {
        Map<PublicKey, LabelGen> Dict = new HashMap<>();
        Field G, Zr;

        public void add(PublicKey pk, LabelGen lg) {
            Dict.put(pk, lg);
        }

        public void get(Label L, PublicKey pk) {
            Element t = G.newRandomElement().getImmutable();
            Element H2_t = H2(Zr, t);
            LabelGen lg = Dict.get(pk);
            L.L = lg.y_1.powZn(H2_t).getImmutable();
            L.R = t.mul(lg.omega_1.powZn(H2_t)).getImmutable();
        }
    }

    public static class PublicKey {
        public Element g, y_2;
    }

    public static class SecretKey {
        public Element alpha, x_1, x_2;
    }

    public static class HashValue {
        public Element S;
    }

    public static class Randomness {
        Element r;
    }

    Field G, Zr;

    private static Element H1(Field G, Element m1, Element m2, Element m3) {
        return Hash.H_PBC_3_1(G, m1, m2, m3);
    }

    private static Element H2(Field G, Element m1) {
        return Hash.H_PBC_1_1(G, m1);
    }

    private Element getHashValue(Randomness r, Label L, PublicKey pk, Element m) {
        return pk.g.powZn(m).
        mul(
            L.L.mul(pk.y_2.powZn(H1(Zr, L.L, L.R, L.L)))
            .powZn(r.r))
        .getImmutable();
    }

    public Element GetGElement() {
        return G.newRandomElement().getImmutable();
    }

    public Element GetZrElement() {
        return Zr.newRandomElement().getImmutable();
    }

    public PBC(LabelManager lm, curve.PBC curve, Group group) {
        Pairing pairing = Func.PairingGen(curve);
        G = Func.GetPBCField(pairing, group);
        Zr = pairing.getZr();
        lm.G = G;
        lm.Zr = Zr;
    }

    public void KeyGen(LabelManager lm, PublicKey pk, SecretKey sk) {
        pk.g = GetGElement();
        sk.alpha = GetZrElement();
        sk.x_1 = GetZrElement();
        sk.x_2 = GetZrElement();
        LabelGen lg = new LabelGen();
        lg.y_1 = pk.g.powZn(sk.x_1).getImmutable();
        lg.omega_1 = lg.y_1.powZn(sk.alpha).getImmutable();
        pk.y_2 = pk.g.powZn(sk.x_2).getImmutable();
        lm.add(pk, lg);
    }

    public void Hash(HashValue h, Randomness r, Label L, LabelManager lm, PublicKey pk, Element m) {
        lm.get(L, pk);
        r.r = GetZrElement();
        h.S = getHashValue(r, L, pk, m);
    }

    public boolean Check(HashValue h, Randomness r, PublicKey pk, Label L, Element m) {
        return h.S.isEqual(getHashValue(r, L, pk, m));
    }

    public void UForge(Randomness r_p, HashValue h, Randomness r, Label L, PublicKey pk, SecretKey sk, Element m, Element m_p) {
        if(!Check(h, r, pk, L, m)) throw new RuntimeException("illegal hash");
        Element t = L.R.div(L.L.powZn(sk.alpha)).getImmutable();
        Element H2_t = H2(Zr, t), c = H1(Zr, L.L, L.R, L.L);
        if(!pk.g.powZn(H2_t.mul(sk.x_1)).isEqual(L.L)) throw new RuntimeException("illegal label");
        r_p.r = r.r.add(
            m.sub(m_p).
            div(
                sk.x_1.mul(H2_t).add(
                    sk.x_2.mul(c)
                    )));
    }

    public void IForge(Randomness r_pp, Randomness r, Randomness r_p, Element m, Element m_p, Element m_pp) {
        r_pp.r = r_p.r.add(
            r_p.r.sub(r.r).
            mul(m_p.sub(m_pp))
            .div(m.sub(m_p))
            );
    }
}
