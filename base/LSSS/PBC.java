package base.LSSS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import utils.BooleanFormulaParser;

@SuppressWarnings("rawtypes")
public class PBC {
    public static class Matrix {
        public Field G;
        public Element[][] M;
        public String[] policy;
        public String formula;

        public static class Vector {
            public Element[] v;
        }

        public Matrix(Field G) {
            this.G = G;
        }

        public void Resize(int n, int m) {
            M = new Element[n][m];
        }

        public Element Prodith(Vector y, int i) {
            Element res = G.newZeroElement().getImmutable();
            for(int j = 0;j < M[i].length;++j) res = res.add(y.v[j].mul(M[i][j])).getImmutable();
            return res;
        }

        public void Solve(Vector x, BooleanFormulaParser.AttributeList S) {
            Vector b = new Vector();
            b.v = new Element[M[0].length];
            b.v[0] = G.newOneElement().getImmutable();
            for (int i = 1; i < M[0].length; i++) b.v[i] = G.newZeroElement().getImmutable();
            Solve(x, b, S);
        }

        public void Solve(Vector x, Vector b, BooleanFormulaParser.AttributeList S) {
            x.v = new Element[M.length];
            for (int i = 0; i < M.length; i++) x.v[i] = G.newZeroElement().getImmutable();
            if(b.v.length != M[0].length) return;
            boolean[] tag = new boolean[M.length];
            int[] col_res = new int[M.length];
            int[] col_index = new int[M.length];
            for(int i = 0; i < M.length; i++) col_index[i] = -1;
            int row_cnt = 0;
            for(int i = 0;i < policy.length;++i) {
                if(S.attrs.contains(policy[i])) {
                    tag[i] = true;
                    col_res[row_cnt] = i;
                    ++row_cnt;
                } else tag[i] = false;
            }
            Element[][] mat = new Element[M[0].length][row_cnt + 1];
            int j = 0;
            for(int i = 0;i < M.length;++i) {
                if(tag[i]) {
                    for(int k = 0;k < M[i].length;++k) mat[k][j] = M[i][k];
                    ++j;
                }
            }
            for(int k = 0;k < M[0].length;++k) mat[k][j] = b.v[k];
            int main_col = 0, i = 0;
            while(main_col < row_cnt) {
                if(mat[i][main_col].isZero()) {
                    for(j = i + 1;j < mat.length;++j) {
                        if(!mat[j][main_col].isZero()) {
                            Element[] tmp = mat[j];
                            mat[j] = mat[i];
                            mat[i] = tmp;
                            break;
                        }
                    }
                }
                if(mat[i][main_col].isZero()) {
                    ++main_col;
                    continue;
                }
                col_index[main_col] = i;
                Element t = mat[i][main_col];
                for(int k = main_col;k < mat[i].length;++k) mat[i][k] = mat[i][k].div(t);
                for(j = 0;j < mat.length;++j) {
                    if(i == j || mat[j][main_col].isZero()) continue;
                    t = mat[j][main_col];
                    for(int k = main_col;k < mat[i].length;++k) mat[j][k] = mat[j][k].sub(mat[i][k].mul(t));
                }
                ++main_col;
                ++i;
            }
            for(i = 0;i < M.length;++i) {
                if(col_index[i] != -1) {
                    x.v[col_res[i]] = mat[col_index[i]][row_cnt];
                }
            }
        }
    }

    public void GenLSSSMatrices(Matrix M, BooleanFormulaParser.PolicyList pi, String BooleanFormulas) {
        BooleanFormulaParser BFParser = new BooleanFormulaParser(BooleanFormulas, pi);
        M.policy = new String[pi.policy.length];
        System.arraycopy(pi.policy, 0, M.policy, 0, M.policy.length);
        BFParser.SetToPBCMatrix(M);
    }
}
