package pkiutil;


import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

/**
 * Created by ligson on 2016/4/22.
 */
public class RSACryptoUtils {
    /**
     * RSA最大加密明文大小,只适应与密钥长度为1024
     */
    private final static int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小,只适应与密钥长度为1024(128),如果是2048写成256
     */
    private final static int MAX_DECRYPT_BLOCK = 256;

    private static byte[] doFinal(int mode, Cipher cipher, byte[] buffer) {
        int maxBlock;
        if (mode == Cipher.ENCRYPT_MODE) {
            maxBlock = MAX_ENCRYPT_BLOCK;
        } else {
            maxBlock = MAX_DECRYPT_BLOCK;
        }

        int inputLen = buffer.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        try {
            // 对数据分段加密
            while (inputLen - offset > 0) {
                if (inputLen - offset > maxBlock) {
                    cache = cipher.doFinal(buffer, offset, maxBlock);
                } else {
                    cache = cipher.doFinal(buffer, offset, inputLen - offset);
                }
                out.write(cache, 0, cache.length);
                i++;
                offset = i * maxBlock;
            }
            out.close();
            return out.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] encrypt(PublicKey publicKey, byte[] buffer) {
        try {
            System.out.println(publicKey);
            // 对数据加密
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedData = doFinal(Cipher.ENCRYPT_MODE, cipher, buffer);
            return encryptedData;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = doFinal(Cipher.DECRYPT_MODE, cipher, encryptedData);
            return decryptedData;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
