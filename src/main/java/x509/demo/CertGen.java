package x509.demo;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Created by ligson on 2016/4/22.
 */
public class CertGen {
    public static X509Certificate gen(SubjectPublicKeyInfo subjectPublicKeyInfo, PrivateKey privateKey, X500Name issuer, X500Name subject, BigInteger serial, Date notBefore, Date notAfter, List<Extension> extensionList) {
        AlgorithmIdentifier signAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE);
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, subjectPublicKeyInfo);
        if (extensionList != null && extensionList.size() > 0) {
            for (Extension extension : extensionList) {
                certificateBuilder.addExtension(extension.getOid(), extension.isCritical(), extension.getValue());
            }
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ContentSigner signer = new ContentSigner() {
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return signAlg;
            }

            @Override
            public OutputStream getOutputStream() {
                return bos;
            }

            @Override
            public byte[] getSignature() {
                return SignService.sign(bos.toByteArray(), "SHA1withRSA", privateKey);
            }
        };
        X509CertificateHolder holder = certificateBuilder.build(signer);
        try {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
            return certificate;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static X509Certificate gen(PublicKey publicKey, PrivateKey privateKey, X500Name issuer, X500Name subject, BigInteger serial, Date notBefore, Date notAfter, List<Extension> extensionList) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        return gen(subjectPublicKeyInfo, privateKey, issuer, subject, serial, notBefore, notAfter, extensionList);
    }
}
