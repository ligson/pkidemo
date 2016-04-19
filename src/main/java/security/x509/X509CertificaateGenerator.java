package security.x509;

import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class X509CertificaateGenerator {
    static {
	Security.addProvider(new BouncyCastleProvider());
    }

    public static Certificate generator(
	    TBSCertificateStructure v3TBSCertificate,
	    AlgorithmIdentifier algSign, byte[] v3TBSCertSignature)
	    throws CertificateParsingException {
	// SM2 Alg oid: 1.2.156.10197.1.301
	// SM3withSM2 Alg oid: 1.2.156.10197.1.501
	if (v3TBSCertificate.getSubjectPublicKeyInfo().getAlgorithmId().getAlgorithm().getId().equals("1.2.156.10197.1.301")) {
	    algSign = new AlgorithmIdentifier("1.2.156.10197.1.501");
	}
	ASN1EncodableVector asn1encodablevector = new ASN1EncodableVector();
	asn1encodablevector.add(v3TBSCertificate);
	asn1encodablevector.add(algSign);
	asn1encodablevector.add(new DERBitString(v3TBSCertSignature));
	return new X509CertificateObject(new X509CertificateStructure(
		new DERSequence(asn1encodablevector)));
    }
}
