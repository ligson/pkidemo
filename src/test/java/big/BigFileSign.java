package big;

import pkiutil.RSACryptoUtils;
import x509.demo.KeyGen;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

/**
 * Created by ligson on 2016/4/22.
 */
public class BigFileSign {
    /**
     * RSA最大加密明文大小,只适应与密钥长度为1024
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小,只适应与密钥长度为1024
     */
    private static final int MAX_DECRYPT_BLOCK = 128;


    public static void main(String[] args) throws Exception {
        File file = new File("h2-1.3.170.sign");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        FileInputStream inputStream = new FileInputStream(file);
        int len;
        while ((len = inputStream.read(buffer)) != -1) {
            bos.write(buffer, 0, len);
        }
        inputStream.close();
        bos.close();
        byte[] source = bos.toByteArray();
        KeyPair pair = KeyGen.gen("RSA", 2048);
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(pair.getPrivate());
        signature.update(source);
        byte[] signData = signature.sign();
        signature.initVerify(pair.getPublic());
        signature.update(source);
        boolean verify = signature.verify(signData);
        System.out.println("签名验证结果:" + verify);

        byte[] encodeData = RSACryptoUtils.encrypt(pair.getPublic(), source);
        System.out.println("加密成功..............");
        byte[] decodeData = RSACryptoUtils.decrypt(pair.getPrivate(), encodeData);
        System.out.println("解密成功..............");
        System.out.println("加密解密比较结果:" + Arrays.equals(decodeData, source));
    }
}
