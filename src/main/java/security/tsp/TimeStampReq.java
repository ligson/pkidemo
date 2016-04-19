package security.tsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.Vector;

/**
 * Base class for an RFC 3161 Time Stamp Request.
 * 
 * <pre>
 * TimeStampReq ::= SEQUENCE  {
 *  version                      INTEGER  { v1(1) },
 *  messageImprint               MessageImprint,
 *    --a hash algorithm OID and the hash value of the data to be
 *    --time-stamped
 *  reqPolicy             TSAPolicyId              OPTIONAL,
 *  nonce                 INTEGER                  OPTIONAL,
 *  certReq               BOOLEAN                  DEFAULT FALSE,
 *  extensions            [0] IMPLICIT Extensions  OPTIONAL
 * }
 * </pre>
 * 
 * @author ShiningWang
 * 
 */
public class TimeStampReq {
	public final static BigInteger V1 = BigInteger.ONE;
	private BigInteger version = V1;
	private MessageImprint messageImprint;
	private TSAPolicyId reqPolicy;
	private BigInteger nonce;
	private boolean certReq = false;
	private TSPExtensions extensions;

	public BigInteger getVersion() {
		return version;
	}

	public void setVersion(BigInteger version) {
		this.version = version;
	}

	public MessageImprint getMessageImprint() {
		return messageImprint;
	}

	public void setMessageImprint(MessageImprint messageImprint) {
		this.messageImprint = messageImprint;
	}

	public TSAPolicyId getReqPolicy() {
		return reqPolicy;
	}

	public void setReqPolicy(TSAPolicyId reqPolicy) {
		this.reqPolicy = reqPolicy;
	}

	public BigInteger getNonce() {
		return nonce;
	}

	public void setNonce(BigInteger nonce) {
		this.nonce = nonce;
	}

	public boolean isCertReq() {
		return certReq;
	}

	public void setCertReq(boolean certReq) {
		this.certReq = certReq;
	}

	public TSPExtensions getExtensions() {
		return extensions;
	}

	public void setExtensions(TSPExtensions extensions) {
		this.extensions = extensions;
	}

	public boolean hasExtensions() {
		return (this.extensions != null);
	}

	public byte[] getEncoded() throws IOException {
		org.bouncycastle.asn1.tsp.MessageImprint bcMsgImprint = null;
		org.bouncycastle.asn1.DERObjectIdentifier derTSAPolicy = null;
		org.bouncycastle.asn1.DERInteger derNonce = null;
		org.bouncycastle.asn1.DERBoolean derCertReq = null;
		org.bouncycastle.asn1.x509.X509Extensions bcX509Extensions = null;
		
		bcMsgImprint = new org.bouncycastle.asn1.tsp.MessageImprint(
				org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(messageImprint
						.getHashAlgorithm().toString()),
				messageImprint.getHashedMessage());
		if (this.reqPolicy != null) {
			derTSAPolicy = new org.bouncycastle.asn1.DERObjectIdentifier(
					this.reqPolicy.toString());
		}
		if (this.nonce != null) {
			derNonce = new org.bouncycastle.asn1.DERInteger(
					this.nonce);
		}
		derCertReq = new org.bouncycastle.asn1.DERBoolean(
				this.certReq);
		if (this.extensions != null) {
			Vector<org.bouncycastle.asn1.ASN1ObjectIdentifier> objectIDs = new Vector<org.bouncycastle.asn1.ASN1ObjectIdentifier>();
			Vector<org.bouncycastle.asn1.x509.X509Extension> values = new Vector<org.bouncycastle.asn1.x509.X509Extension>();
			Iterator<String> it = this.extensions.getCriticalExtensionOIDs()
					.iterator();
			while (it.hasNext()) {
				String oid = it.next();
				objectIDs.add(new org.bouncycastle.asn1.ASN1ObjectIdentifier(
						oid));
				values.add(new org.bouncycastle.asn1.x509.X509Extension(true,
						new org.bouncycastle.asn1.DEROctetString(
								this.extensions.getExtensionValue(oid))));
			}
			it = null; // 释放资源
			it = this.extensions.getNonCriticalExtensionOIDs().iterator();
			while (it.hasNext()) {
				String oid = it.next();
				objectIDs.add(new org.bouncycastle.asn1.ASN1ObjectIdentifier(
						oid));
				values.add(new org.bouncycastle.asn1.x509.X509Extension(false,
						new org.bouncycastle.asn1.DEROctetString(
								this.extensions.getExtensionValue(oid))));
			}
			it = null; // 释放资源
			bcX509Extensions = new org.bouncycastle.asn1.x509.X509Extensions(
					objectIDs, values);
		}

		org.bouncycastle.tsp.TimeStampRequest bcreq = new org.bouncycastle.tsp.TimeStampRequest(
				new org.bouncycastle.asn1.tsp.TimeStampReq(bcMsgImprint,
						derTSAPolicy, derNonce, derCertReq, bcX509Extensions));
		return bcreq.getEncoded();

	}
	public static TimeStampReq getInstance(byte[] bytes) throws IOException {
		return getInstance(new ByteArrayInputStream(bytes));
	}
	public static TimeStampReq getInstance(InputStream is) throws IOException {
		TimeStampReq req = new TimeStampReq();
		org.bouncycastle.tsp.TimeStampRequest bcreq = new org.bouncycastle.tsp.TimeStampRequest(is);
		req.messageImprint = new MessageImprint(
				bcreq.getMessageImprintAlgOID(),
				bcreq.getMessageImprintDigest());
        if(bcreq.getReqPolicy()!=null)
	    	req.reqPolicy = new TSAPolicyId(bcreq.getReqPolicy());
        if(bcreq.getNonce()!=null)
		    req.nonce = bcreq.getNonce();
	    req.certReq = bcreq.getCertReq();
		if (bcreq.hasExtensions()) {
			req.extensions = new TSPExtensions();
			Iterator<?> it = bcreq.getCriticalExtensionOIDs().iterator();
			while (it.hasNext()) {
				String oid = (String) it.next();
				req.extensions.add(oid, bcreq.getExtensionValue(oid), true);
			}
			it = null; // 释放资源
			it = bcreq.getNonCriticalExtensionOIDs().iterator();
			while (it.hasNext()) {
				String oid = (String) it.next();
				req.extensions.add(oid, bcreq.getExtensionValue(oid), false);
			}
		}
		return req;
	}
}
