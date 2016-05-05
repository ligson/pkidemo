package x509.demo;

import javax.crypto.Cipher;
import javax.crypto.ExemptionMechanism;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.util.Arrays;

/**
 * Created by ligson on 2016/5/5.
 */
public class CipherTest {
    public static void main(String[] args) throws Exception {
        String plain = "lecxe123_";
        //KeyPair keyPair = KeyGen.gen("RSA", 1024);

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        SecretKey key = generator.generateKey();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        System.out.println(Arrays.toString(iv));
        int blockSize = cipher.getBlockSize();
        System.out.println(blockSize);
        ExemptionMechanism mechanism = cipher.getExemptionMechanism();
        System.out.println(mechanism);
        AlgorithmParameters parameters = cipher.getParameters();
        System.out.println(parameters);
        cipher.update(plain.getBytes());
        byte[] buffer = cipher.doFinal();
        cipher.init(Cipher.DECRYPT_MODE, key);
        cipher.update(buffer);
        byte[] source = cipher.doFinal();
        System.out.println(new String(source));


    }
}
