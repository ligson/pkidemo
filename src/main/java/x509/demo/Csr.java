package x509.demo;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator;
import org.bouncycastle.operator.ContentSigner;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

/**
 * Created by ligson on 2016/4/18.
 */
public class Csr {
    static {
        System.out.println(Providers.provider);
    }


    public static String genCsr(KeyPair keyPair, X500Name subject) throws Exception {
        //生成csr
        X500Principal principal = new X500Principal(subject.getEncoded());
        PKCS10CertificationRequest request = new PKCS10CertificationRequest("SHA1withRSA", principal, keyPair.getPublic(), null, keyPair.getPrivate());
        System.out.println(request);
        String code = "-----BEGIN CERTIFICATE REQUEST-----\n";
        String csr = Base64.encodeBase64String(request.getEncoded());
        code += csr;
        code += "\n-----END CERTIFICATE REQUEST-----\n";
        System.out.println(code);

        FileOutputStream fos = new FileOutputStream(new File("111.csr"));
        fos.write(code.getBytes());
        fos.close();
        return csr;
    }

    public static PKCS10CertificationRequest readCsr(String csr) throws Exception {
        byte[] buffer = Base64.decodeBase64(csr);
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(buffer);
        System.out.println(request);

        System.out.println(request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        return request;
    }

    public static X509Certificate genCert(X500Name issuer, KeyPair issuerKeyPair, String csr, String fileName, List<Extension> extensionList) throws Exception {
        PKCS10CertificationRequest request = readCsr(csr);
        CertificationRequestInfo requestInfo = request.getCertificationRequestInfo();

        X500Name subject = X500Name.getInstance(requestInfo.getSubject().getEncoded());


        BigInteger serial = BigInteger.probablePrime(32, new Random());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 24
                * 60 * 60 * 1000L);
        X509Certificate certificate = CertGen.genV3(requestInfo
                .getSubjectPublicKeyInfo(), issuerKeyPair.getPrivate(), issuer, subject, serial, notBefore, notAfter, extensionList);
        File file = new File(fileName);
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(certificate.getEncoded());
        fos.close();
        System.out.println(certificate);

        certificate.verify(issuerKeyPair.getPublic());
        System.out.println("verify ok........");
        return certificate;
    }

    public static void main(String[] args) throws Exception {
        List<Extension> extensions = new ArrayList<>();
        extensions.add(new Extension(X509Extension.basicConstraints, false, new BasicConstraints(3)));
        //颁发root证书
        KeyPair rootKeyPair = JksKeyStore.getKeyPair("key1");
        X500Name rootSubject = X500NameGen.gen("sk", "dev", "localhost");
        String rootCsr = genCsr(rootKeyPair, rootSubject);
        X509Certificate rootCert = genCert(rootSubject, rootKeyPair, rootCsr, "root.cer", extensions);

        //颁发二级证书
        //KeyPair secondKeyPair = JksKeyStore.getKeyPair("key2");
        //X500Name secondSubject = X500NameGen.gen("sk", "dev", "second");
        //String secondCsr = genCsr(secondKeyPair, secondSubject);
        //X509Certificate secondCert = genCert(rootSubject, rootKeyPair,secondCsr, "second.cer", extensions);

        //颁发三级证书
        //KeyPair thirdKeyPair = JksKeyStore.getKeyPair("key3");
        //X500Name thirdSubject = X500NameGen.gen("sk", "dev", "third");
        //String thirdCsr = genCsr(thirdKeyPair, thirdSubject);
        //X509Certificate thirdCert = genCert(secondSubject, secondKeyPair,thirdCsr, "third.cer", extensions);

        //颁发用户证书
        KeyPair userKeyPair = JksKeyStore.getKeyPair("key");
        X500Name userSubject = X500NameGen.gen("sk", "dev", "user");
        String userCsr = genCsr(userKeyPair, userSubject);
        X509Certificate userCert = genCert(rootSubject, rootKeyPair, userCsr, "user" +
                ".cer", null);

        char[] pwd = "password".toCharArray();
        //服务器证书
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(null, null);
        keyStore.setKeyEntry("root", rootKeyPair.getPrivate(), pwd, new Certificate[]{rootCert});
        keyStore.store(new FileOutputStream("keystore.jks"), pwd);

        //可信证书
        //keyStore.setKeyEntry("second", secondKeyPair.getPrivate(), pwd, new Certificate[]{rootCert, secondCert});
        //keyStore.setKeyEntry("third", thirdKeyPair.getPrivate(), pwd, new Certificate[]{rootCert, secondCert, thirdCert});
        keyStore.setCertificateEntry("user", userCert);
        keyStore.store(new FileOutputStream("truststore.jks"), pwd);

    }
}
