package security.bc.operator;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import security.x509.AlgorithmId;

public final class NullContentSigner implements ContentSigner {
	private static final byte[] B0 = new byte[0];

	private NullContentSigner() {
	}

	static final NullContentSigner INSTANCE = new NullContentSigner();

	public static final NullContentSigner getInstance() {
		return INSTANCE;
	}

	public AlgorithmIdentifier getAlgorithmIdentifier() {
		return new AlgorithmIdentifier(AlgorithmId.UNASSIGNED.toString());
	}

	public OutputStream getOutputStream() {
		return new NullOutputStream();
	}

	public byte[] getSignature() {
		return B0;
	}
}

class NullOutputStream extends OutputStream {
	@Override
	public void write(byte[] buf) throws IOException {
		// do nothing
	}

	@Override
	public void write(byte[] buf, int off, int len) throws IOException {
		// do nothing
	}

	@Override
	public void write(int b) throws IOException {
		// do nothing
	}
}
