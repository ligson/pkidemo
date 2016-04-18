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
    static BouncyCastleProvider provider = new BouncyCastleProvider();

    static {
        Security.addProvider(provider);
    }

    public static void main(String[] args) throws Exception {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", provider);
        //keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(publicKey);
        System.out.println(privateKey);

        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.CN,"ligson");
        nameBuilder.addRDN(BCStyle.OU,"dev");
        nameBuilder.addRDN(BCStyle.O,"sk");

        X500Name issuer = nameBuilder.build();

        BigInteger serial = BigInteger.probablePrime(32, new Random());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 24
                * 60 * 60 * 1000L);
        X500Name subject = issuer;
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(new ASN1InputStream(publicKey.getEncoded()).readObject());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, subjectPublicKeyInfo);


        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        ContentSigner signer = new ContentSigner() {
            //XCN_OID_RSA_SHA1RSA (1.2.840.113549.1.1.5)_1.2.840.113549.1.1.1
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
            }

            @Override
            public OutputStream getOutputStream() {
                return buffer;
            }

            @Override
            public byte[] getSignature() {
                System.out.println(Arrays.toString(buffer.toByteArray()));
                return SignService.sign(buffer.toByteArray(), "SHA1withRSA", keyPair.getPrivate());
            }
        };

        X509CertificateHolder holder = builder.build(signer);
        File file = new File("11.cer");
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(holder.getEncoded());
        fos.close();
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
        System.out.println(certificate);
    }
}
