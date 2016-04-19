package security.bc.cms;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class CMSSignedDataUtil {
	private static Provider provider;
	static {
		provider = Security.getProvider("BC");
		if (provider == null)
			provider = new BouncyCastleProvider();
		if (provider.getVersion() != 1.46) {
			throw new RuntimeException("needs bouncy castale v1.46");
		} else {
			Security.addProvider(provider);
		}
	}

	public static CMSSignedData genCMSSignedDate(byte[] plaintext,
			String signAlgorithm, PrivateKey privateKey, Certificate signCert,
			Certificate[] certChain, CRL[] crls, Provider provider)
			throws CertificateEncodingException, IOException,
			OperatorCreationException, CMSException, CRLException {
		if (provider == null)
			provider = CMSSignedDataUtil.provider;
		List certList = new ArrayList();
		if (plaintext == null)
			plaintext = new byte[0];
		CMSTypedData msg = new CMSProcessableByteArray(plaintext);
		X509CertificateHolder signCertHolder = new X509CertificateHolder(
				signCert.getEncoded());
		certList.add(signCertHolder);
		if (certChain != null)
			for (int i = 0; i < certChain.length; i++) {
				certList.add(new X509CertificateHolder(certChain[i]
						.getEncoded()));
			}
		Store certs = new JcaCertStore(certList);
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		ContentSigner signer = null;
		if (privateKey != null)
			signer = new JcaContentSignerBuilder(signAlgorithm).setProvider(
					provider).build(privateKey);
		gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().setProvider(provider)
						.build()).build(signer, signCertHolder));
		gen.addCertificates(certs);
		if (crls != null) {
			List crlList = new ArrayList();
			for (int i = 0; i < crls.length; i++) {
				crlList.add(new X509CRLHolder(((X509CRL) crls[i]).getEncoded()));
			}
			Store crlstore = new JcaCRLStore(crlList);
			gen.addCRLs(crlstore);
		}
		return gen.generate(msg, false);
	}

	public static void verifyCMSSignedData(byte[] plaintext,
			CMSSignedData data, Provider provider)
			throws OperatorCreationException, CertificateException,
			CMSException {
		ContentInfo contentInfo = data.getContentInfo();
		DEREncodable dEREncodable = contentInfo.getContent();
		if (dEREncodable != null) {
			// contentInfo.getContentType().equals(ContentInfo.data)
			DEROctetString dEROctetString = (DEROctetString) dEREncodable;
			plaintext = dEROctetString.getOctets();
		}
		System.out.println(new String("plaintext"));
		if (provider == null)
			provider = CMSSignedDataUtil.provider;
		Store certStore = data.getCertificates();
		SignerInformationStore signers = data.getSignerInfos();
		Collection c = signers.getSigners();
		Iterator it = c.iterator();
		int count = 0, verified = 0;
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			Collection certCollection = certStore.getMatches(signer.getSID());

			Iterator certIt = certCollection.iterator();
			X509CertificateHolder cert = (X509CertificateHolder) certIt.next();

			if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
					.setProvider(provider).build(cert))) {
				verified++;
			}
			count++;
		}
		if (verified != count) {
			throw new CMSException(count + " signer found, but " + verified
					+ " is verified.");
		}
	}

}
