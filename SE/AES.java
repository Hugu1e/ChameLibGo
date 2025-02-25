package SE;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AES {
    public static class CipherText {
        public byte[] ct;
    }

    public static class PlainText {
        public byte[] pt;
    }

    private static Cipher GetCipher(int mode, byte[] key) throws Exception {
        SecretKeySpec skspec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(mode, skspec);
        return cipher;
    }

    public static void Encrypt(CipherText ct, PlainText pt, byte[] key) {
        try {
            ct.ct = GetCipher(Cipher.ENCRYPT_MODE, key).doFinal(pt.pt);
        } catch (Exception e) {
            throw new RuntimeException("ERR in AES");
        }
    }

    public static void Decrypt(PlainText pt, CipherText ct, byte[] key) {
        try {
            pt.pt = GetCipher(Cipher.DECRYPT_MODE, key).doFinal(ct.ct);
        } catch (Exception e) {
            throw new RuntimeException("ERR in AES");
        }
    }
}
