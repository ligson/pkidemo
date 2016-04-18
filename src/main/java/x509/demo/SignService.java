package x509.demo;

import java.security.PrivateKey;
import java.security.Signature;

/**
 * Created by ligson on 2016/4/18.
 */
public class SignService {
    public static byte[] sign(byte[] plainText, String signAlg, PrivateKey privateKey) {
        try {
            Signature sign = Signature.getInstance(signAlg);
            sign.initSign(privateKey);
            sign.update(plainText);
            return sign.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }
}
