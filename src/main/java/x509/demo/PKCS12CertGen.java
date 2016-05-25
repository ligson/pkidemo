package x509.demo;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
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
        jks.load(new FileInputStream("truststore.jks"), pwd);
        Certificate userCert = jks.getCertificate("user");
        PrivateKey privateKey = JksKeyStore.getKeyPair("key4").getPrivate();
        System.out.println("用户撕咬:" + privateKey);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("user", privateKey, pwd, new Certificate[]{userCert});
        keyStore.store(new FileOutputStream(new File("user.p12")), pwd);

        X509Name x509Name = new X509Name("O=org,OU=unit,CN=user");

        System.out.println(x509Name);
        X500Name x500Name = X500Name.getInstance(x509Name.getEncoded());
        System.out.println(x500Name);
    }
}
