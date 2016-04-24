package x509.demo;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.jce.examples.PKCS12Example;
import org.bouncycastle.jce.provider.JDKPKCS12KeyStore;
import sun.security.rsa.RSAPrivateCrtKeyImpl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

/**
 * Created by ligso on 2016/4/24.
 */
public class PKCS12CertGen {
    static {
        System.out.println(Providers.provider);
    }

    public static void main(String[] args) throws Exception {
        char[] pwd = "password".toCharArray();
        KeyStore jks = KeyStore.getInstance("jks");
        jks.load(new FileInputStream("keystore.jks"), pwd);
        X509Certificate rootCert = (X509Certificate) jks.getCertificate("root");
        Certificate[] userCert = jks.getCertificateChain
                ("user");
        PrivateKey privateKey = (PrivateKey) jks.getKey("user", pwd);
        System.out.println("用户撕咬:" + privateKey);
        RSAPrivateCrtKeyImpl rsaPrivateCrtKey = (RSAPrivateCrtKeyImpl) privateKey;
        System.out.println(rsaPrivateCrtKey.getFormat());

        KeyPair rootKeyPair = JksKeyStore.getKeyPair("key1");
        //userCert.verify(rootKeyPair.getPublic());
        System.out.println("root cert verify success.....");
        //PKCS12Example.main(args);
        System.out.println("chain");
        for (Certificate certificate : userCert) {
            System.out.println(((X509Certificate) certificate).getSubjectDN());
        }
        System.out.println("root:" + rootCert.getSubjectDN());
        //Certificate[] chain = new Certificate[]{userCert, rootCert};
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("user", privateKey, pwd, userCert);
        keyStore.store(new FileOutputStream(new File("user.p12")), pwd);

    }
}
