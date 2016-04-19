package security.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestHolder;
import org.bouncycastle.util.encoders.Base64;

import security.bc.operator.JcaContentSignerBuilder;
import security.bc.operator.NullContentSigner;
import security.x509.AlgorithmId;
import pkiutil.NoMatchingException;

public class CertUtil {

	/**
	 * 从网络或文件获取CRL
	 * 
	 * @param crlUrl
	 * @return
	 * @throws CertificateException
	 * @throws CRLException
	 * @throws IOException
	 */
	public static CRL getCRL(String crlUrl) throws CertificateException,
			CRLException, IOException {
		URL crlURL = null;
		try {
			crlURL = new URL(crlUrl);
		} catch (MalformedURLException e) {
			String message = e.getMessage();
			if (message.indexOf("unknown protocol") >= 0) {
				// try to use file protocol
				crlURL = new URL("File:///".concat(crlUrl));
			} else {
				throw e;
			}
		}
		CRL crl = conertCRL(crlURL.openConnection().getInputStream());
		return crl;
	}

	/**
	 * 用正则提取证书主题内容
	 * 
	 * @param certificate
	 * @param regex
	 * @param groupIndex
	 * @return
	 * @throws NoMatchingException
	 */
	public static String matchSubject(Certificate certificate, String regex,
			int groupIndex) throws NoMatchingException {
		X509Certificate x509cert = (X509Certificate) certificate;
		Pattern p = Pattern.compile(regex);
		Matcher match = p.matcher(x509cert.getSubjectDN().getName());
		if (match.find()) {
			return match.group(groupIndex);
		}
		throw new NoMatchingException(
				"No matching from the certificate. @SerialNumber: "
						.concat(x509cert.getSerialNumber().toString(16)));
	}

	/**
	 * 转换PEM编码证书
	 * 
	 * @param certificatePEMBuffer
	 * @return
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static Certificate conertCertificate(String certificatePEMBuffer)
			throws CertificateException, IOException {
		if (certificatePEMBuffer.contains(BEGIN_CERT)) {
			certificatePEMBuffer = certificatePEMBuffer.substring(
					CertUtil.BEGIN_CERT.length(),
					certificatePEMBuffer.indexOf(CertUtil.END_CERT));
		}
		certificatePEMBuffer = certificatePEMBuffer.replaceAll("\\s", "");
		ByteArrayInputStream bais = new ByteArrayInputStream(
				Base64.decode(certificatePEMBuffer));
		return conertCertificate(bais);
	}

	/**
	 * 转换文件证书
	 * 
	 * @param certificatePEMBuffer
	 * @return
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static Certificate conertCertificate(File certFile)
			throws CertificateException, IOException {
		return conertCertificate(new FileInputStream(certFile));
	}

	/**
	 * 转换DER编码证书
	 * 
	 * @param certificatePEMBuffer
	 * @return
	 * @throws CertificateException
	 * @throws IOException
	 */
	public static Certificate conertCertificate(byte[] derBuf)
			throws CertificateException, IOException {
		return conertCertificate(new ByteArrayInputStream(derBuf));
	}

	public static BigInteger conertCertSerialnumber(String serialnumber) {
		return new BigInteger(serialnumber.replaceAll("[^0-9|^a-f|^A-F]", ""),
				16);
	}

	/**
	 * 证书对象进行标准编码 PEM输出
	 * 
	 * @param cert
	 * @param pem
	 * @param out
	 * @throws IOException
	 * @throws CertificateException
	 */
	public static void storeCert(Certificate cert, boolean pem, PrintStream out)
			throws IOException, CertificateException {
		if (pem = false) {
			out.println(CertUtil.BEGIN_CERT);
			Base64.encode(cert.getEncoded(), out);
			out.println(CertUtil.END_CERT);
		} else {
			out.write(cert.getEncoded()); // binary
		}
	}

	public static Certificate conertCertificate(InputStream in)
			throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		return cf.generateCertificate(in);
	}

	public static Certificate[] conertCertChain(InputStream in)
			throws CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		Collection<?> c = cf.generateCertificates(in);
		return (Certificate[]) c.toArray(new Certificate[c.size() - 1]);
	}

	public static CRL conertCRL(InputStream in) throws CRLException,
			CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		return cf.generateCRL(in);
	}

	/**
	 * 生成X509证书请求
	 * 参数：[密钥对|公钥私钥|公钥][主题X500Name][算法String][加密提供者Provider][证书开始时间Date]
	 * [证书有效期long(秒)]
	 * 
	 * @param args
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws CertificateEncodingException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 * @throws IOException
	 */
	public static void genCSR(String subjectName, PublicKey subjectPublicKey,
			String issureName, PrivateKey issurePrivateKey, String sigAlgName,
			PrintStream out, Provider provider) throws Exception {
		SubjectPublicKeyInfo publicKeyInfo;
		String signatureAlgorithm;
		if (subjectPublicKey.getAlgorithm().equals("SM2")) {
			publicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
					AlgorithmId.SM2_oid.toString()),
					subjectPublicKey.getEncoded());
			signatureAlgorithm = "SM3withSM2";
		} else {
			publicKeyInfo = new SubjectPublicKeyInfo(
					DERSequence.getInstance(subjectPublicKey.getEncoded()));
			signatureAlgorithm = "SHA1with" + subjectPublicKey.getAlgorithm();
		}

		X500Name subject = new X500Name(subjectName);
		PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(
				subject, publicKeyInfo);
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
				.setProvider(provider).build(issurePrivateKey);
		PKCS10CertificationRequestHolder holder = csrBuilder.build(signer);
		out.write(holder.getEncoded());
	}

	public static Certificate wrapToCertContainer(PublicKey publicKey) {
		String keyAlg;
		try {
			keyAlg = AlgorithmId.get(publicKey.getAlgorithm()).getOID()
					.toString();
		} catch (NoSuchAlgorithmException e) {
			keyAlg = publicKey.getAlgorithm();
		}
		byte[] keyBuffer = publicKey.getEncoded();
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			// can not be happened
			e.printStackTrace();
		}
		byte[] publicKeyHash = md.digest(keyBuffer);
		String subjectDN = "CN={SHA1}" + Hex.encodeHexString(publicKeyHash)
				+ ", OU=R&D Center, O=TopCA";
		String issureDN = "CN=PublicKey Container, OU=R&D Center, O=TopCA";

		SubjectPublicKeyInfo publicKeyInfo;
		AlgorithmId keyAlgId;
		try {
			keyAlgId = AlgorithmId.get(keyAlg);
		} catch (NoSuchAlgorithmException e) {
			// can not be happened, but...
			throw new RuntimeException(e);
		}
		if (keyAlgId.getName().equals("SM2")) {
			publicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
					keyAlg), keyBuffer);
		} else {
			publicKeyInfo = new SubjectPublicKeyInfo(
					ASN1Sequence.getInstance(keyBuffer));
		}
		X500Name issuer, subject;
		subject = new X500Name(subjectDN);
		issuer = new X500Name(issureDN);
		BigInteger serial = new BigInteger(publicKeyHash);
		Date notBefore = new Date();
		long year = 365 * 24 * 60 * 60 * 1000;
		Date notAfter = new Date(notBefore.getTime() + 10 * year);
		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
				issuer, serial, notBefore, notAfter, subject, publicKeyInfo);
		ContentSigner signer = NullContentSigner.getInstance();
		X509CertificateHolder certHolder = certBuilder.build(signer);
		byte[] certBuf = null;
		try {
			certBuf = certHolder.getEncoded();
		} catch (IOException e) {
			e.printStackTrace();
		}
		try {
			X509Certificate cert = (X509Certificate) CertificateFactory
					.getInstance("X509").generateCertificate(
							new ByteArrayInputStream(certBuf));
			return cert;
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERT = "-----END CERTIFICATE-----";
}
