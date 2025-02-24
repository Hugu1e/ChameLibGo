package base.LSSS;

import utils.BooleanFormulaParser;

import java.util.Arrays;

/*
 * Decentralizing Attribute-Based Encryption
 * P30. G Converting from Boolean Formulas to LSSS Matrices
 */

public class Native {
    public static class Matrix {
        public short[][] M;

        public void Resize(int n, int m) {
            M = new short[n][m];
        }

        public void Print() {
            System.out.println("Matrix:");
            for (short[] shorts : M) {
                System.out.println(Arrays.toString(shorts));
            }
            System.out.println();
        }
    }

    public void GenLSSSMatrices(Matrix M, BooleanFormulaParser.PolicyList pi, String BooleanFormulas) {
        BooleanFormulaParser BFParser = new BooleanFormulaParser(BooleanFormulas, pi);
        BFParser.SetToNativeMatrix(M);
    }
}
