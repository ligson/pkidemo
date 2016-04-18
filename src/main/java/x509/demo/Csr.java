package x509.demo;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator;
import org.bouncycastle.operator.ContentSigner;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

/**
 * Created by ligson on 2016/4/18.
 */
public class Csr {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void genCsr() throws Exception {
        //生成密钥对
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        //生成csr
        X500Principal principal = new X500Principal("O=baidu;OU=dev;CN=ligson");
        PKCS10CertificationRequest request = new PKCS10CertificationRequest("SHA1withRSA", principal, keyPair.getPublic(), null, keyPair.getPrivate());
        System.out.println(request);
        String code = "-----BEGIN CERTIFICATE REQUEST-----\n";
        code += Base64.encodeBase64String(request.getEncoded());
        code += "\n-----END CERTIFICATE REQUEST-----\n";
        System.out.println(code);

        FileOutputStream fos = new FileOutputStream(new File("111.csr"));
        fos.write(code.getBytes());
        fos.close();
    }

    public static PKCS10CertificationRequest readCsr() throws Exception {
        String csr = "MIIBbDCB1gIBADAvMQ8wDQYDVQQDEwZsaWdzb24xDDAKBgNVBAsTA2RldjEOMAwGA1UEChMFYmFpZHUwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAI1R1sph6uCXaQP5mPVnMjgGDWtNOVQUKY6BKupPCYSV0ri2lCgHH0dIy4PPLqdBg1hECxG0jLKyH3ZIViCjxX2UbSXgY2lzIoJNpZQmxDR9C2G9Wn2O0cf/oFVYFB4GboG/uVMvBBqwdtLt3FRgh+U6st9pLbOgVaoB+q5AJYXrAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAis0/j+6Ma2b4ZK2fKm1Vimj03l4vAzAiGbgpi2gocLH04SpuiBfebT+AtzOvh8dOLr4fQ4/BIIdyycU2FDe7T7H4V+B7SfgDCzmImx4zfPpC01mCZHpT9o1pcbYuvi41XGUnWvrdctVL+whlIf85TW3sbNAucMKfbYnxXWg+MMc=";
        byte[] buffer = Base64.decodeBase64(csr);
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(buffer);
        System.out.println(request);

        System.out.println(request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        return request;
    }

    public static void main(String[] args) throws Exception {
        PKCS10CertificationRequest request = readCsr();
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN,"ligson");
        builder.addRDN(BCStyle.OU,"dev");
        builder.addRDN(BCStyle.O,"sk");
        X500Name issuer = builder.build();
        BigInteger serial = BigInteger.probablePrime(32, new Random());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 24
                * 60 * 60 * 1000L);
        //ASN1Object asn1Object = ASN1Sequence.fromByteArray(request.getCertificationRequestInfo().getSubject().getEncoded());
        X500Name subject =X500Name.getInstance(request.getCertificationRequestInfo().getSubject().getEncoded());
        System.out.println(issuer);

        //csr生成证书
        X509v3CertificateBuilder builder1 = new X509v3CertificateBuilder(issuer, BigInteger.probablePrime(32,new Random()),notBefore,notAfter,subject,request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
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
                //CA private key
                return SignService.sign(buffer.toByteArray(), "SHA1withRSA", null);
            }
        };

        X509CertificateHolder holder = builder1.build(signer);
        File file = new File("11.cer");
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(holder.getEncoded());
        fos.close();
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
        System.out.println(certificate);
    }
}
