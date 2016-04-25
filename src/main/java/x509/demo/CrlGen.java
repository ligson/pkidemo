package x509.demo;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.X509CRLObject;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

/**
 * Created by ligson on 2016/4/25.
 */
public class CrlGen {
    public static void main(String[] args) throws Exception {

        V2TBSCertListGenerator generator = new V2TBSCertListGenerator();
        X500Name subject = X500NameGen.gen("sk", "dev", "root");
        generator.setIssuer(subject);
        Calendar calendar = Calendar.getInstance();
        generator.setThisUpdate(new Time(calendar.getTime()));
        calendar.add(Calendar.DAY_OF_MONTH, 1);
        Date next = calendar.getTime();
        generator.setNextUpdate(new Time(next));
        AlgorithmIdentifier signAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE);
        generator.setSignature(signAlg);
        generator.addCRLEntry(new DERInteger(BigInteger.probablePrime(32, new Random())),
                new Time(calendar.getTime()),
                CRLReason.superseded, new DERGeneralizedTime(calendar.getTime()));
        ASN1EncodableVector asn1encodablevector = new ASN1EncodableVector();
        asn1encodablevector.add(generator.generateTBSCertList());
        byte[] signBuffer = SignService.sign(generator.generateTBSCertList().getEncoded(), "SHA1withRSA", JksKeyStore.getKeyPair("key1").getPrivate());
        asn1encodablevector.add(new DERBitString(signBuffer));


        X509CRLObject crl = new X509CRLObject(new CertificateList(new DERSequence(
                asn1encodablevector)));
        System.out.println(crl);
    }
}
