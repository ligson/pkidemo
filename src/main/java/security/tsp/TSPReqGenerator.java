package security.tsp;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.Vector;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;

import security.x509.X509ExtensionIdentifier;
import security.x509.X509Extensions;

public class TSPReqGenerator {
	private X509Extensions extensions;
	private boolean certReq;
	public X509Extensions getExtensions() {
		return extensions;
	}

	public void setExtensions(X509Extensions extensions) {
		this.extensions = extensions;
	}

	public boolean isCertReq() {
		return certReq;
	}

	public void setCertReq(boolean certReq) {
		this.certReq = certReq;
	}

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	private String identifier;
	
	public TimeStampReq generate(X509ExtensionIdentifier identifier, byte[] digest,BigInteger nonce) throws IOException{
		return this.generate(identifier.toString(), digest, nonce);
	}
	public TimeStampReq generate(String digestAlgorithmOID, byte[] digest,BigInteger nonce) throws IOException{

		TimeStampReq tsReq =  new TimeStampReq();
		DERObjectIdentifier digestAlgOID = new DERObjectIdentifier(digestAlgorithmOID);

		org.bouncycastle.asn1.x509.AlgorithmIdentifier algID = 
			new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
					digestAlgOID, 
					new DERNull());
		
		org.bouncycastle.asn1.tsp.MessageImprint mImprint = 
			new org.bouncycastle.asn1.tsp.MessageImprint(algID,digest);

		Vector<org.bouncycastle.asn1.ASN1ObjectIdentifier> objectIDs = new Vector<org.bouncycastle.asn1.ASN1ObjectIdentifier>();
		Vector<org.bouncycastle.asn1.x509.X509Extension> values = new Vector<org.bouncycastle.asn1.x509.X509Extension>();
		Iterator<String> it = extensions.getCriticalExtensionOIDs()
		.iterator();
		while (it.hasNext()) {
			String oid = it.next();
			objectIDs.add(new org.bouncycastle.asn1.ASN1ObjectIdentifier(oid));
			values.add(new org.bouncycastle.asn1.x509.X509Extension(true,
					new org.bouncycastle.asn1.DEROctetString(extensions
							.getExtensionValue(oid))));
		}
		it = null; // 释放资源

		org.bouncycastle.tsp.TimeStampRequest bcreq = new org.bouncycastle.tsp.TimeStampRequest(
				new org.bouncycastle.asn1.tsp.TimeStampReq(mImprint,
						new DERObjectIdentifier(this.identifier),
						new org.bouncycastle.asn1.DERInteger(nonce),
						new org.bouncycastle.asn1.DERBoolean(certReq),
						new org.bouncycastle.asn1.x509.X509Extensions(
								objectIDs, values)));

		if (bcreq.hasExtensions()) {
			tsReq.setExtensions(new TSPExtensions());
			Iterator<?> its = bcreq.getCriticalExtensionOIDs().iterator();
			while (its.hasNext()) {
				String oid = (String) its.next();
				tsReq.getExtensions().add(oid, bcreq.getExtensionValue(oid), true);
			}
			its = null; // 释放资源
			its = bcreq.getNonCriticalExtensionOIDs().iterator();
			while (its.hasNext()) {
				String oid = (String) its.next();
				tsReq.getExtensions().add(oid, bcreq.getExtensionValue(oid), false);
			}
		}
		tsReq.setMessageImprint(new security.tsp.MessageImprint(
				bcreq.getMessageImprintAlgOID(),
				bcreq.getMessageImprintDigest()));

		tsReq.setReqPolicy(new TSAPolicyId(bcreq.getReqPolicy()));
		tsReq.setNonce(bcreq.getNonce());
		tsReq.setCertReq(bcreq.getCertReq());

		return tsReq;
	}
}
