package security.sm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import security.x509.AlgorithmId;

public class TopSMProvider extends Provider {

	private static final double version = 1.0;
	public static final String NAME = "TopSM";
	private static final String info = NAME + " Security Provider v" + version;

	public TopSMProvider() {
		// First, register provider name, version and description.
		super(NAME, version, info);
		// Set up the provider properties
		String className;
		// ------------------- SM Algorithms -------------------
		final String smImpPackage = "security.sm.";

		// SM2 key pair algorithm
		final String sm2Name = "SM2";
		final String sm2_oid = AlgorithmId.SM2_oid.toString();
		final String sm3whitsm2Name = "SM3withSM2";
		final String sm3withsm2_oid = AlgorithmId.SM3withSM2_oid.toString();
		/* AlgorithmParameters */
		className = "SM2Parameters";
		put(algAlias + algParams + sm2_oid, sm2Name);
		put(algParams + sm2_oid, smImpPackage + className);
		put(algParams + sm2Name, smImpPackage + className);
		/* KeyFactory */
		className = "SM2KeyFactory";
		put(algAlias + keyFactory + sm2_oid, sm2Name);
		put(keyFactory + sm2_oid, smImpPackage + className);
		put(keyFactory + sm2Name, smImpPackage + className);
		/* KeyPairGenerator */
		className = "SM2KeyPairGenerator";
		put(algAlias + keyPairGen + sm2_oid, sm2Name);
		put(keyPairGen + sm2_oid, smImpPackage + className);
		put(keyPairGen + sm2Name, smImpPackage + className);
		/* Cipher */
		className = "SM2Cipher";
		put(algAlias + cipher + sm2_oid, sm2Name);
		put(cipher + sm2_oid, smImpPackage + className);
		put(cipher + sm2Name, smImpPackage + className);
		put(cipher + sm2Name + " SupportedModes", "NONE");
		put(cipher + sm2Name + " SupportedPaddings", "NOPADDING");
		put(cipher + sm2Name + " SupportedKeyClasses",
				"security.sm.SM2PublicKey|security.sm.SM2PrivateKey");
		put(cipher + sm2Name + " SupportedKeyFormats", "RAW");
		/* Signature */
		className = "SM2Signature$SM3withSM2";
		put(algAlias + signature + sm3withsm2_oid, sm3whitsm2Name);
		put(signature + sm3withsm2_oid, smImpPackage + className);
		put(signature + sm3whitsm2Name, smImpPackage + className);

		// SM3 message digest algorithm
		final String sm3Name = "SM3";
		final String sm3_oid = AlgorithmId.SM3_oid.toString();
		/* MessageDigest */
		className = "SM3MessageDigest";
		put(algAlias + digest + sm3_oid, sm3Name);
		put(digest + sm3_oid, smImpPackage + className);
		put(digest + sm3Name, smImpPackage + className);

		// SMS4 symmetric key algorithm
		final String sms4Name = "SMS4";
		final String sms4_oid = "1.2.156.10197.1.104";
		/* KeyGenerator */
		className = "SMS4KeyGenerator";
		put(algAlias + keyGen + sms4_oid, sms4Name);
		put(keyGen + sms4_oid, smImpPackage + className);
		put(keyGen + sms4Name, smImpPackage + className);
		/* Cipher */
		className = "SMS4Cipher";
		put(algAlias + cipher + sms4_oid, sms4Name);
		put(cipher + sms4_oid, smImpPackage + className);
		put(cipher + sms4Name, smImpPackage + className);

		// verifiedSelfIntegrity = JarVerifier.verify(TopSMProvider.class);
	}

	private static final String algAlias = "Alg.Alias.";
	private static final String algParams = "AlgorithmParameters.";
	private static final String keyFactory = "KeyFactory.";
	private static final String keyPairGen = "KeyPairGenerator.";
	private static final String keyGen = "KeyGenerator";
	private static final String signature = "Signature.";
	private static final String cipher = "Cipher.";
	private static final String digest = "MessageDigest.";

	private static final long serialVersionUID = -7445881625380917033L;

	// static void ensureIntegrity(Class<?> c) {
	// if (JarVerifier.verify(c) == false) {
	// throw new SecurityException("The " + NAME + " provider may have "
	// + "been tampered.");
	// }
	// }

	// Flag for avoiding unnecessary self-integrity checking.
	@SuppressWarnings("unused")
	private static boolean verifiedSelfIntegrity = false;

	// Provider's signing cert which is used to sign the jar.
	private static X509Certificate providerCert = null;

	// Raw bytes of provider's own code signing cert.
	// NOTE: YOU NEED TO CHANGE THIS TO YOUR OWN PROVIDER CERTIFICATE
	private static final byte[] bytesOfProviderCert = { (byte) 0x30,
			(byte) 0x82, (byte) 0x03, (byte) 0xB4, (byte) 0x30, (byte) 0x82,
			(byte) 0x03, (byte) 0x72, (byte) 0xA0, (byte) 0x03, (byte) 0x02,
			(byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x01,
			(byte) 0x04, (byte) 0x30, (byte) 0x0B, (byte) 0x06, (byte) 0x07,
			(byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x38,
			(byte) 0x04, (byte) 0x03, (byte) 0x05, (byte) 0x00, (byte) 0x30,
			(byte) 0x81, (byte) 0x90, (byte) 0x31, (byte) 0x0B, (byte) 0x30,
			(byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04,
			(byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x55, (byte) 0x53,
			(byte) 0x31, (byte) 0x0B, (byte) 0x30, (byte) 0x09, (byte) 0x06,
			(byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x08, (byte) 0x13,
			(byte) 0x02, (byte) 0x43, (byte) 0x41, (byte) 0x31, (byte) 0x12,
			(byte) 0x30, (byte) 0x10, (byte) 0x06, (byte) 0x03, (byte) 0x55,
			(byte) 0x04, (byte) 0x07, (byte) 0x13, (byte) 0x09, (byte) 0x50,
			(byte) 0x61, (byte) 0x6C, (byte) 0x6F, (byte) 0x20, (byte) 0x41,
			(byte) 0x6C, (byte) 0x74, (byte) 0x6F, (byte) 0x31, (byte) 0x1D,
			(byte) 0x30, (byte) 0x1B, (byte) 0x06, (byte) 0x03, (byte) 0x55,
			(byte) 0x04, (byte) 0x0A, (byte) 0x13, (byte) 0x14, (byte) 0x53,
			(byte) 0x75, (byte) 0x6E, (byte) 0x20, (byte) 0x4D, (byte) 0x69,
			(byte) 0x63, (byte) 0x72, (byte) 0x6F, (byte) 0x73, (byte) 0x79,
			(byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x6D, (byte) 0x73,
			(byte) 0x20, (byte) 0x49, (byte) 0x6E, (byte) 0x63, (byte) 0x31,
			(byte) 0x23, (byte) 0x30, (byte) 0x21, (byte) 0x06, (byte) 0x03,
			(byte) 0x55, (byte) 0x04, (byte) 0x0B, (byte) 0x13, (byte) 0x1A,
			(byte) 0x4A, (byte) 0x61, (byte) 0x76, (byte) 0x61, (byte) 0x20,
			(byte) 0x53, (byte) 0x6F, (byte) 0x66, (byte) 0x74, (byte) 0x77,
			(byte) 0x61, (byte) 0x72, (byte) 0x65, (byte) 0x20, (byte) 0x43,
			(byte) 0x6F, (byte) 0x64, (byte) 0x65, (byte) 0x20, (byte) 0x53,
			(byte) 0x69, (byte) 0x67, (byte) 0x6E, (byte) 0x69, (byte) 0x6E,
			(byte) 0x67, (byte) 0x31, (byte) 0x1C, (byte) 0x30, (byte) 0x1A,
			(byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03,
			(byte) 0x13, (byte) 0x13, (byte) 0x4A, (byte) 0x43, (byte) 0x45,
			(byte) 0x20, (byte) 0x43, (byte) 0x6F, (byte) 0x64, (byte) 0x65,
			(byte) 0x20, (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6E,
			(byte) 0x69, (byte) 0x6E, (byte) 0x67, (byte) 0x20, (byte) 0x43,
			(byte) 0x41, (byte) 0x30, (byte) 0x1E, (byte) 0x17, (byte) 0x0D,
			(byte) 0x30, (byte) 0x31, (byte) 0x31, (byte) 0x30, (byte) 0x31,
			(byte) 0x39, (byte) 0x32, (byte) 0x33, (byte) 0x30, (byte) 0x34,
			(byte) 0x33, (byte) 0x31, (byte) 0x5A, (byte) 0x17, (byte) 0x0D,
			(byte) 0x30, (byte) 0x36, (byte) 0x31, (byte) 0x30, (byte) 0x32,
			(byte) 0x33, (byte) 0x32, (byte) 0x33, (byte) 0x30, (byte) 0x34,
			(byte) 0x33, (byte) 0x31, (byte) 0x5A, (byte) 0x30, (byte) 0x63,
			(byte) 0x31, (byte) 0x1D, (byte) 0x30, (byte) 0x1B, (byte) 0x06,
			(byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0A, (byte) 0x0C,
			(byte) 0x14, (byte) 0x53, (byte) 0x75, (byte) 0x6E, (byte) 0x20,
			(byte) 0x4D, (byte) 0x69, (byte) 0x63, (byte) 0x72, (byte) 0x6F,
			(byte) 0x73, (byte) 0x79, (byte) 0x73, (byte) 0x74, (byte) 0x65,
			(byte) 0x6D, (byte) 0x73, (byte) 0x20, (byte) 0x49, (byte) 0x6E,
			(byte) 0x63, (byte) 0x31, (byte) 0x23, (byte) 0x30, (byte) 0x21,
			(byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0B,
			(byte) 0x0C, (byte) 0x1A, (byte) 0x4A, (byte) 0x61, (byte) 0x76,
			(byte) 0x61, (byte) 0x20, (byte) 0x53, (byte) 0x6F, (byte) 0x66,
			(byte) 0x74, (byte) 0x77, (byte) 0x61, (byte) 0x72, (byte) 0x65,
			(byte) 0x20, (byte) 0x43, (byte) 0x6F, (byte) 0x64, (byte) 0x65,
			(byte) 0x20, (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6E,
			(byte) 0x69, (byte) 0x6E, (byte) 0x67, (byte) 0x31, (byte) 0x1D,
			(byte) 0x30, (byte) 0x1B, (byte) 0x06, (byte) 0x03, (byte) 0x55,
			(byte) 0x04, (byte) 0x03, (byte) 0x0C, (byte) 0x14, (byte) 0x53,
			(byte) 0x75, (byte) 0x6E, (byte) 0x20, (byte) 0x4D, (byte) 0x69,
			(byte) 0x63, (byte) 0x72, (byte) 0x6F, (byte) 0x73, (byte) 0x79,
			(byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x6D, (byte) 0x73,
			(byte) 0x20, (byte) 0x49, (byte) 0x6E, (byte) 0x63, (byte) 0x30,
			(byte) 0x82, (byte) 0x01, (byte) 0xB5, (byte) 0x30, (byte) 0x82,
			(byte) 0x01, (byte) 0x2A, (byte) 0x06, (byte) 0x05, (byte) 0x2B,
			(byte) 0x0E, (byte) 0x03, (byte) 0x02, (byte) 0x0C, (byte) 0x30,
			(byte) 0x82, (byte) 0x01, (byte) 0x1F, (byte) 0x02, (byte) 0x81,
			(byte) 0x81, (byte) 0x00, (byte) 0xFD, (byte) 0x7F, (byte) 0x53,
			(byte) 0x81, (byte) 0x1D, (byte) 0x75, (byte) 0x12, (byte) 0x29,
			(byte) 0x52, (byte) 0xDF, (byte) 0x4A, (byte) 0x9C, (byte) 0x2E,
			(byte) 0xEC, (byte) 0xE4, (byte) 0xE7, (byte) 0xF6, (byte) 0x11,
			(byte) 0xB7, (byte) 0x52, (byte) 0x3C, (byte) 0xEF, (byte) 0x44,
			(byte) 0x00, (byte) 0xC3, (byte) 0x1E, (byte) 0x3F, (byte) 0x80,
			(byte) 0xB6, (byte) 0x51, (byte) 0x26, (byte) 0x69, (byte) 0x45,
			(byte) 0x5D, (byte) 0x40, (byte) 0x22, (byte) 0x51, (byte) 0xFB,
			(byte) 0x59, (byte) 0x3D, (byte) 0x8D, (byte) 0x58, (byte) 0xFA,
			(byte) 0xBF, (byte) 0xC5, (byte) 0xF5, (byte) 0xBA, (byte) 0x30,
			(byte) 0xF6, (byte) 0xCB, (byte) 0x9B, (byte) 0x55, (byte) 0x6C,
			(byte) 0xD7, (byte) 0x81, (byte) 0x3B, (byte) 0x80, (byte) 0x1D,
			(byte) 0x34, (byte) 0x6F, (byte) 0xF2, (byte) 0x66, (byte) 0x60,
			(byte) 0xB7, (byte) 0x6B, (byte) 0x99, (byte) 0x50, (byte) 0xA5,
			(byte) 0xA4, (byte) 0x9F, (byte) 0x9F, (byte) 0xE8, (byte) 0x04,
			(byte) 0x7B, (byte) 0x10, (byte) 0x22, (byte) 0xC2, (byte) 0x4F,
			(byte) 0xBB, (byte) 0xA9, (byte) 0xD7, (byte) 0xFE, (byte) 0xB7,
			(byte) 0xC6, (byte) 0x1B, (byte) 0xF8, (byte) 0x3B, (byte) 0x57,
			(byte) 0xE7, (byte) 0xC6, (byte) 0xA8, (byte) 0xA6, (byte) 0x15,
			(byte) 0x0F, (byte) 0x04, (byte) 0xFB, (byte) 0x83, (byte) 0xF6,
			(byte) 0xD3, (byte) 0xC5, (byte) 0x1E, (byte) 0xC3, (byte) 0x02,
			(byte) 0x35, (byte) 0x54, (byte) 0x13, (byte) 0x5A, (byte) 0x16,
			(byte) 0x91, (byte) 0x32, (byte) 0xF6, (byte) 0x75, (byte) 0xF3,
			(byte) 0xAE, (byte) 0x2B, (byte) 0x61, (byte) 0xD7, (byte) 0x2A,
			(byte) 0xEF, (byte) 0xF2, (byte) 0x22, (byte) 0x03, (byte) 0x19,
			(byte) 0x9D, (byte) 0xD1, (byte) 0x48, (byte) 0x01, (byte) 0xC7,
			(byte) 0x02, (byte) 0x15, (byte) 0x00, (byte) 0x97, (byte) 0x60,
			(byte) 0x50, (byte) 0x8F, (byte) 0x15, (byte) 0x23, (byte) 0x0B,
			(byte) 0xCC, (byte) 0xB2, (byte) 0x92, (byte) 0xB9, (byte) 0x82,
			(byte) 0xA2, (byte) 0xEB, (byte) 0x84, (byte) 0x0B, (byte) 0xF0,
			(byte) 0x58, (byte) 0x1C, (byte) 0xF5, (byte) 0x02, (byte) 0x81,
			(byte) 0x81, (byte) 0x00, (byte) 0xF7, (byte) 0xE1, (byte) 0xA0,
			(byte) 0x85, (byte) 0xD6, (byte) 0x9B, (byte) 0x3D, (byte) 0xDE,
			(byte) 0xCB, (byte) 0xBC, (byte) 0xAB, (byte) 0x5C, (byte) 0x36,
			(byte) 0xB8, (byte) 0x57, (byte) 0xB9, (byte) 0x79, (byte) 0x94,
			(byte) 0xAF, (byte) 0xBB, (byte) 0xFA, (byte) 0x3A, (byte) 0xEA,
			(byte) 0x82, (byte) 0xF9, (byte) 0x57, (byte) 0x4C, (byte) 0x0B,
			(byte) 0x3D, (byte) 0x07, (byte) 0x82, (byte) 0x67, (byte) 0x51,
			(byte) 0x59, (byte) 0x57, (byte) 0x8E, (byte) 0xBA, (byte) 0xD4,
			(byte) 0x59, (byte) 0x4F, (byte) 0xE6, (byte) 0x71, (byte) 0x07,
			(byte) 0x10, (byte) 0x81, (byte) 0x80, (byte) 0xB4, (byte) 0x49,
			(byte) 0x16, (byte) 0x71, (byte) 0x23, (byte) 0xE8, (byte) 0x4C,
			(byte) 0x28, (byte) 0x16, (byte) 0x13, (byte) 0xB7, (byte) 0xCF,
			(byte) 0x09, (byte) 0x32, (byte) 0x8C, (byte) 0xC8, (byte) 0xA6,
			(byte) 0xE1, (byte) 0x3C, (byte) 0x16, (byte) 0x7A, (byte) 0x8B,
			(byte) 0x54, (byte) 0x7C, (byte) 0x8D, (byte) 0x28, (byte) 0xE0,
			(byte) 0xA3, (byte) 0xAE, (byte) 0x1E, (byte) 0x2B, (byte) 0xB3,
			(byte) 0xA6, (byte) 0x75, (byte) 0x91, (byte) 0x6E, (byte) 0xA3,
			(byte) 0x7F, (byte) 0x0B, (byte) 0xFA, (byte) 0x21, (byte) 0x35,
			(byte) 0x62, (byte) 0xF1, (byte) 0xFB, (byte) 0x62, (byte) 0x7A,
			(byte) 0x01, (byte) 0x24, (byte) 0x3B, (byte) 0xCC, (byte) 0xA4,
			(byte) 0xF1, (byte) 0xBE, (byte) 0xA8, (byte) 0x51, (byte) 0x90,
			(byte) 0x89, (byte) 0xA8, (byte) 0x83, (byte) 0xDF, (byte) 0xE1,
			(byte) 0x5A, (byte) 0xE5, (byte) 0x9F, (byte) 0x06, (byte) 0x92,
			(byte) 0x8B, (byte) 0x66, (byte) 0x5E, (byte) 0x80, (byte) 0x7B,
			(byte) 0x55, (byte) 0x25, (byte) 0x64, (byte) 0x01, (byte) 0x4C,
			(byte) 0x3B, (byte) 0xFE, (byte) 0xCF, (byte) 0x49, (byte) 0x2A,
			(byte) 0x03, (byte) 0x81, (byte) 0x84, (byte) 0x00, (byte) 0x02,
			(byte) 0x81, (byte) 0x80, (byte) 0x07, (byte) 0xCC, (byte) 0xF6,
			(byte) 0x38, (byte) 0x3A, (byte) 0xCD, (byte) 0xD3, (byte) 0x58,
			(byte) 0x99, (byte) 0x90, (byte) 0x0F, (byte) 0x71, (byte) 0xAF,
			(byte) 0xAA, (byte) 0xD0, (byte) 0x03, (byte) 0x27, (byte) 0x3B,
			(byte) 0x74, (byte) 0xE1, (byte) 0x64, (byte) 0x38, (byte) 0x11,
			(byte) 0xBF, (byte) 0xFA, (byte) 0xB7, (byte) 0xBF, (byte) 0x2C,
			(byte) 0xE7, (byte) 0xBB, (byte) 0xA7, (byte) 0x92, (byte) 0x2F,
			(byte) 0x08, (byte) 0xCE, (byte) 0x27, (byte) 0xF8, (byte) 0xB4,
			(byte) 0xFD, (byte) 0xD8, (byte) 0x14, (byte) 0x1D, (byte) 0xA3,
			(byte) 0x95, (byte) 0xBB, (byte) 0x03, (byte) 0x16, (byte) 0xA6,
			(byte) 0xBA, (byte) 0xBC, (byte) 0x35, (byte) 0xC0, (byte) 0xCD,
			(byte) 0xF9, (byte) 0xF5, (byte) 0x6C, (byte) 0xA7, (byte) 0x94,
			(byte) 0x5B, (byte) 0x23, (byte) 0x01, (byte) 0xF9, (byte) 0xAE,
			(byte) 0xF5, (byte) 0xC9, (byte) 0xE0, (byte) 0x81, (byte) 0x7A,
			(byte) 0xE8, (byte) 0xE4, (byte) 0x69, (byte) 0xEB, (byte) 0xF8,
			(byte) 0xF5, (byte) 0x80, (byte) 0x25, (byte) 0x04, (byte) 0x2C,
			(byte) 0x91, (byte) 0x73, (byte) 0x96, (byte) 0x59, (byte) 0xB4,
			(byte) 0x06, (byte) 0x83, (byte) 0x17, (byte) 0xB2, (byte) 0x50,
			(byte) 0xAC, (byte) 0x4F, (byte) 0xEB, (byte) 0x9D, (byte) 0x51,
			(byte) 0x25, (byte) 0x3D, (byte) 0xF7, (byte) 0xEE, (byte) 0xB0,
			(byte) 0x24, (byte) 0x25, (byte) 0x0E, (byte) 0xFE, (byte) 0xB4,
			(byte) 0x32, (byte) 0xA1, (byte) 0xC4, (byte) 0x0E, (byte) 0xB3,
			(byte) 0x66, (byte) 0x41, (byte) 0xE0, (byte) 0x57, (byte) 0xCE,
			(byte) 0x9D, (byte) 0xBE, (byte) 0x33, (byte) 0x2E, (byte) 0x93,
			(byte) 0x9A, (byte) 0xC9, (byte) 0x7A, (byte) 0x57, (byte) 0xDC,
			(byte) 0xCD, (byte) 0x88, (byte) 0x60, (byte) 0xA7, (byte) 0xCE,
			(byte) 0xA3, (byte) 0x81, (byte) 0x88, (byte) 0x30, (byte) 0x81,
			(byte) 0x85, (byte) 0x30, (byte) 0x11, (byte) 0x06, (byte) 0x09,
			(byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x86,
			(byte) 0xF8, (byte) 0x42, (byte) 0x01, (byte) 0x01, (byte) 0x04,
			(byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x04, (byte) 0x10,
			(byte) 0x30, (byte) 0x0E, (byte) 0x06, (byte) 0x03, (byte) 0x55,
			(byte) 0x1D, (byte) 0x0F, (byte) 0x01, (byte) 0x01, (byte) 0xFF,
			(byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x05,
			(byte) 0xE0, (byte) 0x30, (byte) 0x1D, (byte) 0x06, (byte) 0x03,
			(byte) 0x55, (byte) 0x1D, (byte) 0x0E, (byte) 0x04, (byte) 0x16,
			(byte) 0x04, (byte) 0x14, (byte) 0x55, (byte) 0x8D, (byte) 0x1F,
			(byte) 0x2A, (byte) 0x05, (byte) 0xAB, (byte) 0x9B, (byte) 0xCE,
			(byte) 0x86, (byte) 0x10, (byte) 0xAE, (byte) 0x3B, (byte) 0x5D,
			(byte) 0xF6, (byte) 0xBA, (byte) 0x3F, (byte) 0x22, (byte) 0xC5,
			(byte) 0x6A, (byte) 0xCA, (byte) 0x30, (byte) 0x1F, (byte) 0x06,
			(byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x23, (byte) 0x04,
			(byte) 0x18, (byte) 0x30, (byte) 0x16, (byte) 0x80, (byte) 0x14,
			(byte) 0x65, (byte) 0xE2, (byte) 0xF4, (byte) 0x86, (byte) 0xC9,
			(byte) 0xD3, (byte) 0x4E, (byte) 0xF0, (byte) 0x91, (byte) 0x4E,
			(byte) 0x58, (byte) 0xA2, (byte) 0x6A, (byte) 0xF5, (byte) 0xD8,
			(byte) 0x78, (byte) 0x5A, (byte) 0x9A, (byte) 0xC1, (byte) 0xA6,
			(byte) 0x30, (byte) 0x20, (byte) 0x06, (byte) 0x03, (byte) 0x55,
			(byte) 0x1D, (byte) 0x11, (byte) 0x04, (byte) 0x19, (byte) 0x30,
			(byte) 0x17, (byte) 0x81, (byte) 0x15, (byte) 0x79, (byte) 0x75,
			(byte) 0x2D, (byte) 0x63, (byte) 0x68, (byte) 0x69, (byte) 0x6E,
			(byte) 0x67, (byte) 0x2E, (byte) 0x70, (byte) 0x65, (byte) 0x6E,
			(byte) 0x67, (byte) 0x40, (byte) 0x73, (byte) 0x75, (byte) 0x6E,
			(byte) 0x2E, (byte) 0x63, (byte) 0x6F, (byte) 0x6D, (byte) 0x30,
			(byte) 0x0B, (byte) 0x06, (byte) 0x07, (byte) 0x2A, (byte) 0x86,
			(byte) 0x48, (byte) 0xCE, (byte) 0x38, (byte) 0x04, (byte) 0x03,
			(byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x2F, (byte) 0x00,
			(byte) 0x30, (byte) 0x2C, (byte) 0x02, (byte) 0x14, (byte) 0x75,
			(byte) 0x4B, (byte) 0xE8, (byte) 0x21, (byte) 0x37, (byte) 0x78,
			(byte) 0x79, (byte) 0x0A, (byte) 0xD0, (byte) 0xB5, (byte) 0xDC,
			(byte) 0x7E, (byte) 0x36, (byte) 0x75, (byte) 0xB9, (byte) 0xE4,
			(byte) 0x14, (byte) 0xB5, (byte) 0xD0, (byte) 0x46, (byte) 0x02,
			(byte) 0x14, (byte) 0x6A, (byte) 0x51, (byte) 0xDC, (byte) 0xBA,
			(byte) 0x6D, (byte) 0x1A, (byte) 0x6B, (byte) 0x5C, (byte) 0x18,
			(byte) 0x23, (byte) 0x6A, (byte) 0xF1, (byte) 0xCA, (byte) 0x21,
			(byte) 0x8A, (byte) 0x77, (byte) 0xC2, (byte) 0x05, (byte) 0x16,
			(byte) 0x42 };

	// /**
	// * Perform self-integrity checking. Call this method in all the
	// constructors
	// * of your SPI implementation classes. NOTE: The following implementation
	// * assumes that all your provider implementation is packaged inside ONE
	// jar.
	// */
	// static final synchronized boolean integrityChecking(final Class<?> clazz)
	// {
	// // Make sure that the provider JAR file is signed with
	// // provider's own signing certificate.
	// try {
	// if (providerCert == null) {
	// providerCert = setupProviderCert();
	// }
	// return verifiedSelfIntegrity && JarVerifier.verify(clazz);
	// } catch (Exception e) {
	// e.printStackTrace();
	// return false;
	// }
	// }

	/*
	 * Set up 'providerCert' with the certificate bytes.
	 */
	@SuppressWarnings("unused")
	private static X509Certificate setupProviderCert() throws IOException,
			CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream inStream = new ByteArrayInputStream(
				bytesOfProviderCert);
		X509Certificate cert = (X509Certificate) cf
				.generateCertificate(inStream);
		inStream.close();
		return cert;
	}

	static class JarVerifier {

		/**
		 * Retrive the jar file from the specified url.
		 */
		private static JarFile retrieveJarFileFromURL(URL url)
				throws PrivilegedActionException, MalformedURLException {
			JarFile jf = null;

			// Prep the url with the appropriate protocol.
			final URL jarURL = url.getProtocol().equalsIgnoreCase("jar") ? url
					: new URL("jar:" + url.toString() + "!/");
			// Retrieve the jar file using JarURLConnection
			jf = AccessController
					.doPrivileged(new PrivilegedExceptionAction<JarFile>() {
						public JarFile run() throws Exception {
							JarURLConnection conn = (JarURLConnection) jarURL
									.openConnection();
							// Always get a fresh copy, so we don't have to
							// worry about the stale file handle when the
							// cached jar is closed by some other application.
							conn.setUseCaches(false);
							return conn.getJarFile();
						}
					});
			return jf;
		}

		private static URL getClassURL(final Class<?> clazz) {
			return AccessController.doPrivileged(new PrivilegedAction<URL>() {
				public URL run() {
					CodeSource cs = clazz.getProtectionDomain().getCodeSource();
					return cs.getLocation();
				}
			});
		}

		/**
		 * First, retrieve the jar file from the URL passed in constructor.
		 * Then, compare it to the expected X509Certificate. If everything went
		 * well and the certificates are the same, no exception is thrown.
		 */
		static boolean verify(final Class<?> clazz) {
			URL classURL = getClassURL(clazz);
			if (classURL == null) {
				return false;
			}
			// Sanity checking
			if (providerCert == null) {
				throw new SecurityException("Provider certificate is invalid");
			}

			JarFile jarFile = null;
			try {
				jarFile = retrieveJarFileFromURL(classURL);

				Vector<JarEntry> entriesVec = new Vector<JarEntry>();

				// Ensure the jar file is signed.
				Manifest man = jarFile.getManifest();
				if (man == null) {
					throw new SecurityException("The provider is not signed");
				}

				// Ensure all the entries' signatures verify correctly
				byte[] buffer = new byte[8192];
				Enumeration<JarEntry> entries = jarFile.entries();

				while (entries.hasMoreElements()) {
					JarEntry je = (JarEntry) entries.nextElement();

					// Skip directories.
					if (je.isDirectory())
						continue;
					entriesVec.addElement(je);
					InputStream is = jarFile.getInputStream(je);

					// Read in each jar entry. A security exception will
					// be thrown if a signature/digest check fails.
					@SuppressWarnings("unused")
					int n;
					while ((n = is.read(buffer, 0, buffer.length)) != -1) {
						// Don't care
					}
					is.close();
				}

				// Get the list of signer certificates
				Enumeration<JarEntry> e = entriesVec.elements();

				while (e.hasMoreElements()) {
					JarEntry je = (JarEntry) e.nextElement();

					// Every file must be signed except files in META-INF.
					Certificate[] certs = je.getCertificates();
					if ((certs == null) || (certs.length == 0)) {
						if (!je.getName().startsWith("META-INF"))
							throw new SecurityException("The provider "
									+ "has unsigned " + "class files.");
					} else {
						// Check whether the file is signed by the expected
						// signer. The jar may be signed by multiple signers.
						// See if one of the signers is 'targetCert'.
						int startIndex = 0;
						X509Certificate[] certChain;
						boolean signedAsExpected = false;

						while ((certChain = getAChain(certs, startIndex)) != null) {
							if (certChain[0].equals(providerCert)) {
								// Stop since one trusted signer is found.
								signedAsExpected = true;
								break;
							}
							// Proceed to the next chain.
							startIndex += certChain.length;
						}

						if (!signedAsExpected) {
							throw new SecurityException("The provider "
									+ "is not signed by a " + "trusted signer");
						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			} finally {
				try {
					if (jarFile != null)
						jarFile.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			return true;
		}

		/**
		 * Extracts ONE certificate chain from the specified certificate array
		 * which may contain multiple certificate chains, starting from index
		 * 'startIndex'.
		 */
		private static X509Certificate[] getAChain(Certificate[] certs,
				int startIndex) {
			if (startIndex > certs.length - 1)
				return null;

			int i;
			// Keep going until the next certificate is not the
			// issuer of this certificate.
			for (i = startIndex; i < certs.length - 1; i++) {
				if (!((X509Certificate) certs[i + 1]).getSubjectDN().equals(
						((X509Certificate) certs[i]).getIssuerDN())) {
					break;
				}
			}
			// Construct and return the found certificate chain.
			int certChainSize = (i - startIndex) + 1;
			X509Certificate[] ret = new X509Certificate[certChainSize];
			for (int j = 0; j < certChainSize; j++) {
				ret[j] = (X509Certificate) certs[startIndex + j];
			}
			return ret;
		}

	}
}
