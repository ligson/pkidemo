package x509.demo;

import com.alibaba.fastjson.util.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.tls.ExtensionType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import sun.security.x509.AlgorithmId;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

/**
 * Created by ligson on 2016/4/18.
 */
public class GenRootCert {

    public static void main(String[] args) throws Exception {
        JksKeyStore.load();
        KeyPair keyPair = JksKeyStore.getKeyPair("key1");
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(publicKey);
        System.out.println(privateKey);

        X500Name subject = X500NameGen.gen("sk", "dev", "root");


        BigInteger serial = BigInteger.probablePrime(32, new Random());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 24
                * 60 * 60 * 1000L);

        X509Certificate certificate = CertGen.gen(publicKey, privateKey, subject, subject, serial, notBefore, notAfter, null);

        File file = new File("root.cer");
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(certificate.getEncoded());
        fos.close();
        System.out.println(certificate);
    }
}
