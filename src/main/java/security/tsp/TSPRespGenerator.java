package security.tsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;


import security.pkix.PKIFailureInfo;
import security.pkix.PKIStatus;
import security.pkix.PKIStatusInfo;

public class TSPRespGenerator {

	private int status;
	private int failInfo;
	private String[] statusStrings;
	private PrivateKey privateKey;
	private X509Certificate x509Cert;
	private String  tsaPolicyOID;
	private String provider;

	public TimeStampResp generate(TimeStampReq request,BigInteger serialNumber,Date genTime)throws IOException, TSPException, TSPException{
		TimeStampResp tsResp =null;
		org.bouncycastle.asn1.cms.ContentInfo tstTokenContentInfo = null;
		org.bouncycastle.asn1.tsp.MessageImprint bcMsgImprint = null;
		org.bouncycastle.asn1.DERObjectIdentifier derTSAPolicy = null;
		org.bouncycastle.asn1.DERInteger derNonce = null;
		org.bouncycastle.asn1.DERBoolean derCertReq = null;
		org.bouncycastle.asn1.x509.X509Extensions bcX509Extensions = null;

		bcMsgImprint = new org.bouncycastle.asn1.tsp.MessageImprint(
				org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(request.getMessageImprint()
						.getHashAlgorithm().toString()),
						request.getMessageImprint().getHashedMessage());
		if (request.getReqPolicy() != null) {
			derTSAPolicy = new org.bouncycastle.asn1.DERObjectIdentifier(
					request.getReqPolicy().toString());
		}
		if (request.getNonce() != null) {
			derNonce = new org.bouncycastle.asn1.DERInteger(
					request.getNonce());
		}
		derCertReq = new org.bouncycastle.asn1.DERBoolean(
				request.isCertReq());
		if (request.getExtensions() != null) {
			Vector<org.bouncycastle.asn1.ASN1ObjectIdentifier> objectIDs = new Vector<org.bouncycastle.asn1.ASN1ObjectIdentifier>();
			Vector<org.bouncycastle.asn1.x509.X509Extension> values = new Vector<org.bouncycastle.asn1.x509.X509Extension>();
			Iterator<String> it = request.getExtensions().getCriticalExtensionOIDs()
			.iterator();
			while (it.hasNext()) {
				String oid = it.next();
				objectIDs.add(new org.bouncycastle.asn1.ASN1ObjectIdentifier(
						oid));
				values.add(new org.bouncycastle.asn1.x509.X509Extension(true,
						new org.bouncycastle.asn1.DEROctetString(
								request.getExtensions().getExtensionValue(oid))));
			}
			it = null; // 释放资源
		}
		org.bouncycastle.tsp.TimeStampRequest bcreq = new org.bouncycastle.tsp.TimeStampRequest(
				new org.bouncycastle.asn1.tsp.TimeStampReq(bcMsgImprint,
						derTSAPolicy, derNonce, derCertReq, bcX509Extensions));

		org.bouncycastle.tsp.TimeStampTokenGenerator tsTokenGen;

		try
		{
			tsTokenGen = new org.bouncycastle.tsp.TimeStampTokenGenerator(
					new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder().build("SHA1withRSA", privateKey, x509Cert), 
					new org.bouncycastle.asn1.ASN1ObjectIdentifier(tsaPolicyOID));
			tsTokenGen.generate(bcreq, serialNumber, genTime);
			ByteArrayInputStream    bIn = new ByteArrayInputStream(tsTokenGen.generate(bcreq, serialNumber, genTime, provider).toCMSSignedData().getEncoded());
			org.bouncycastle.asn1.ASN1InputStream         aIn = new org.bouncycastle.asn1.ASN1InputStream(bIn);

			tstTokenContentInfo = org.bouncycastle.asn1.cms.ContentInfo.getInstance(aIn.readObject());
		} catch (Exception e) {
			throw new TSPException(
					"Timestamp token received cannot be converted to ContentInfo", e);
		} 

		try {
			security.pkix.PKIFreeText ifreeText = null;
			if(statusStrings!=null && statusStrings.length<=0)
				ifreeText = new security.pkix.PKIFreeText(statusStrings);
			PKIFailureInfo failureInfo = null;
			if(failInfo!=0)
				failureInfo  = new PKIFailureInfo(failInfo);
			tsResp = new TimeStampResp(
					new PKIStatusInfo(new PKIStatus(status),
							ifreeText, 
							failureInfo),
							new security.tsp.TimeStampToken(
									tstTokenContentInfo));
		} catch (org.bouncycastle.tsp.TSPException e) {
			throw new TSPException(e.getMessage(), e);
		}

		return tsResp;

	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public X509Certificate getX509Cert() {
		return x509Cert;
	}

	public void setX509Cert(X509Certificate x509Cert) {
		this.x509Cert = x509Cert;
	}

	public String getTsaPolicyOID() {
		return tsaPolicyOID;
	}

	public void setTsaPolicyOID(String tsaPolicyOID) {
		this.tsaPolicyOID = tsaPolicyOID;
	}

	public String getProvider() {
		return provider;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}

	public int getStatus() {
		return status;
	}

	public void setStatus(int status) {
		this.status = status;
	}

	public int getFailInfo() {
		return failInfo;
	}

	public void setFailInfo(int failInfo) {
		this.failInfo = failInfo;
	}

	public String[] getStatusStrings() {
		return statusStrings;
	}

	public void setStatusStrings(String[] statusStrings) {
		this.statusStrings = statusStrings;
	}

}
