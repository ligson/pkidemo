package security.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;

import security.util.BitArray;
import security.util.DerOutputStream;
import security.util.DerValue;

public class X509Key implements PublicKey {
	private static final long serialVersionUID = -5359250853002055002L;
	protected AlgorithmId algid;

	protected byte[] key = null;

	private int unusedBits = 0;

	private BitArray bitStringKey = null;
	protected byte[] encodedKey;

	public X509Key() {
	}

	private X509Key(AlgorithmId algid, BitArray key) throws InvalidKeyException {
		this.algid = algid;
		setKey(key);
		encode();
	}

	protected void setKey(BitArray key) {
		this.bitStringKey = ((BitArray) key.clone());

		this.key = key.toByteArray();
		int i = key.length() % 8;
		this.unusedBits = ((i == 0) ? 0 : 8 - i);
	}

	protected BitArray getKey() {
		this.bitStringKey = new BitArray(this.key.length * 8 - this.unusedBits,
				this.key);

		return ((BitArray) this.bitStringKey.clone());
	}

	public static PublicKey parse(DerValue in) throws IOException {
		if (in.tag != 48) {
			throw new IOException("corrupt subject key");
		}
		AlgorithmId algorithm = AlgorithmId.parse(in.data.getDerValue());
		PublicKey subjectKey;
		try {
			subjectKey = buildX509Key(algorithm,
					in.data.getUnalignedBitString());
		} catch (InvalidKeyException e) {
			throw new IOException("subject key, " + e.getMessage());
		}

		if (in.data.available() != 0)
			throw new IOException("excess subject key");
		return subjectKey;
	}

	protected void parseKeyBits() throws IOException, InvalidKeyException {
		encode();
	}

	static PublicKey buildX509Key(AlgorithmId algid, BitArray key)
			throws IOException, InvalidKeyException {
		DerOutputStream x509EncodedKeyStream = new DerOutputStream();
		encode(x509EncodedKeyStream, algid, key);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(
				x509EncodedKeyStream.toByteArray());
		try {
			KeyFactory keyFac = KeyFactory.getInstance(algid.getName());
			return keyFac.generatePublic(x509KeySpec);
		} catch (NoSuchAlgorithmException e) {
			// Return generic X509Key with opaque key data (see below)
		} catch (InvalidKeySpecException e) {
			throw new InvalidKeyException(e.getMessage());
		}

		X509Key result = new X509Key(algid, key);
		return result;
	}

	public String getAlgorithm() {
		return this.algid.getName();
	}

	public AlgorithmId getAlgorithmId() {
		return this.algid;
	}

	public final void encode(DerOutputStream out) throws IOException {
		encode(out, this.algid, getKey());
	}

	public byte[] getEncoded() {
		try {
			return ((byte[]) (byte[]) getEncodedInternal().clone());
		} catch (InvalidKeyException e) {
		}
		return null;
	}

	public byte[] getEncodedInternal() throws InvalidKeyException {
		byte[] encoded = this.encodedKey;
		if (encoded == null) {
			try {
				DerOutputStream out = new DerOutputStream();
				encode(out);
				encoded = out.toByteArray();
			} catch (IOException e) {
				throw new InvalidKeyException("IOException : " + e.getMessage());
			}

			this.encodedKey = encoded;
		}
		return encoded;
	}

	public String getFormat() {
		return "X.509";
	}

	public byte[] encode() throws InvalidKeyException {
		return ((byte[]) (byte[]) getEncodedInternal().clone());
	}

	public String toString() {
		return "algorithm = " + this.algid.toString()
				+ ", unparsed keybits = \n" + new String(Hex.encode(this.key));
	}

	public void decode(InputStream in) throws InvalidKeyException {
		try {
			DerValue val = new DerValue(in);
			if (val.tag != 48) {
				throw new InvalidKeyException("invalid key format");
			}
			this.algid = AlgorithmId.parse(val.data.getDerValue());
			setKey(val.data.getUnalignedBitString());
			parseKeyBits();
			if (val.data.available() != 0)
				throw new InvalidKeyException("excess key data");
		} catch (IOException e) {
			throw new InvalidKeyException("IOException: " + e.getMessage());
		}
	}

	public void decode(byte[] encodedKey) throws InvalidKeyException {
		decode(new ByteArrayInputStream(encodedKey));
	}

	private void writeObject(ObjectOutputStream stream) throws IOException {
		stream.write(getEncoded());
	}

	private void readObject(ObjectInputStream stream) throws IOException {
		try {
			decode(stream);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			throw new IOException("deserialized key is invalid: "
					+ e.getMessage());
		}
	}

	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof Key))
			return false;
		try {
			byte[] thisEncoded = getEncodedInternal();
			byte[] otherEncoded;
			if (obj instanceof X509Key)
				otherEncoded = ((X509Key) obj).getEncodedInternal();
			else {
				otherEncoded = ((Key) obj).getEncoded();
			}
			return Arrays.equals(thisEncoded, otherEncoded);
		} catch (InvalidKeyException e) {
		}
		return false;
	}

	public int hashCode() {
		try {
			byte[] b1 = getEncodedInternal();
			int i = b1.length;
			for (int j = 0; j < b1.length; ++j) {
				i += (b1[j] & 0xFF) * 37;
			}
			return i;
		} catch (InvalidKeyException e) {
		}
		return 0;
	}

	static void encode(DerOutputStream out, AlgorithmId keyAlgId,
			BitArray keyBitArray) throws IOException {
		DerOutputStream stream = new DerOutputStream();
		keyAlgId.encode(stream);
		stream.putUnalignedBitString(keyBitArray);
		out.write((byte) 0x30, stream);
	}
}
