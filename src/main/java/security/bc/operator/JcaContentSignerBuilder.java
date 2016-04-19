package security.bc.operator;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorStreamException;
import org.bouncycastle.operator.RuntimeOperatorException;

import security.x509.AlgorithmId;

public class JcaContentSignerBuilder {
	private SecureRandom random;
	private Provider provider;
	private String signatureAlgorithm;
	private String sigAlgOID;

	public JcaContentSignerBuilder(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
		try {
			this.sigAlgOID = AlgorithmId.get(signatureAlgorithm).getOID()
					.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(
					"Unknown signature type requested: " + signatureAlgorithm,
					e);
		}
	}

	public JcaContentSignerBuilder setProvider(Provider provider) {
		this.provider = provider;
		return this;
	}

	public JcaContentSignerBuilder setProvider(String providerName) {
		this.provider = Security.getProvider(providerName);
		return this;
	}

	public JcaContentSignerBuilder setSecureRandom(SecureRandom random) {
		this.random = random;
		return this;
	}

	public ContentSigner build(PrivateKey privateKey)
			throws OperatorCreationException {
		try {
			final Signature sig;
			if (provider != null) {
				sig = Signature.getInstance(signatureAlgorithm, provider);
			} else {
				sig = Signature.getInstance(signatureAlgorithm);
			}

			if (random != null) {
				sig.initSign(privateKey, random);
			} else {
				sig.initSign(privateKey);
			}

			return new ContentSigner() {
				private SignatureOutputStream stream = new SignatureOutputStream(
						sig);

				public AlgorithmIdentifier getAlgorithmIdentifier() {
					return new AlgorithmIdentifier(sigAlgOID);
				}

				public OutputStream getOutputStream() {
					return stream;
				}

				public byte[] getSignature() {
					try {
						return stream.getSignature();
					} catch (SignatureException e) {
						throw new RuntimeOperatorException(
								"exception obtaining signature: "
										+ e.getMessage(), e);
					}
				}
			};
		} catch (GeneralSecurityException e) {
			throw new OperatorCreationException("cannot create signer: "
					+ e.getMessage(), e);
		}
	}

	private class SignatureOutputStream extends OutputStream {
		private Signature sig;

		SignatureOutputStream(Signature sig) {
			this.sig = sig;
		}

		public void write(byte[] bytes, int off, int len) throws IOException {
			try {
				sig.update(bytes, off, len);
			} catch (SignatureException e) {
				throw new OperatorStreamException(
						"exception in content signer: " + e.getMessage(), e);
			}
		}

		public void write(byte[] bytes) throws IOException {
			try {
				sig.update(bytes);
			} catch (SignatureException e) {
				throw new OperatorStreamException(
						"exception in content signer: " + e.getMessage(), e);
			}
		}

		public void write(int b) throws IOException {
			try {
				sig.update((byte) b);
			} catch (SignatureException e) {
				throw new OperatorStreamException(
						"exception in content signer: " + e.getMessage(), e);
			}
		}

		byte[] getSignature() throws SignatureException {
			return sig.sign();
		}
	}
}
