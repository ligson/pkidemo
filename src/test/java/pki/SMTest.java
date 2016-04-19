package pki;

import crypto.CipherAgent;
import security.sm.SM2Cipher;
import security.sm.SM2GenParameterSpec;
import security.sm.SM2UserID;
import security.sm.TopSMProvider;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Arrays;

/**
 * Created by ligson on 2016/4/19.
 */
public class SMTest {
    public static void main(String[] args) throws Exception {
        //KeyPair生成
        TopSMProvider provider = new TopSMProvider();
        Security.addProvider(provider);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("SM2");
        KeyPair keyPair = generator.generateKeyPair();
        System.out.println(keyPair);
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("pubkey:" + publicKey);
        System.out.println("prikey" + privateKey);

        //cipher
        //Cipher cipher = Cipher.getInstance("SM2",provider);
        String plainText = "hello world";
        CipherAgent cipherAgent = CipherAgent.getInstance("SM2");

        cipherAgent.init(Cipher.ENCRYPT_MODE, publicKey);
        cipherAgent.update(plainText.getBytes());
        byte[] buffer = cipherAgent.doFinal();
        System.out.println("加密的结果:"+Arrays.toString(buffer));
        cipherAgent.init(Cipher.DECRYPT_MODE, privateKey);
        cipherAgent.update(buffer);
        byte[] buffer2 = cipherAgent.doFinal();
        System.out.println("揭秘结果:" + new String(buffer2));

        //sign
        byte[] userId = "1234567812345678".getBytes();
        Signature signature = Signature.getInstance("SM3withSM2");
        signature.initSign(privateKey);
        signature.setParameter(new SM2GenParameterSpec(new SM2UserID(userId),
                publicKey));
        signature.update(buffer);
        byte[] buffer3 = signature.sign();
        signature.initVerify(publicKey);
        signature.setParameter(new SM2GenParameterSpec(new SM2UserID(userId),
                publicKey));
        signature.update(buffer);
        boolean verify = signature.verify(buffer3);
        System.out.println(verify);

        //has
        MessageDigest digest = MessageDigest.getInstance("SM3");
        digest.update(plainText.getBytes());
        byte[] buffer4 = digest.digest();
        System.out.println(Arrays.toString(buffer4));
    }
}
