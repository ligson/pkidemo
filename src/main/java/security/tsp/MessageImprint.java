package security.tsp;

import java.io.IOException;

import security.AlgorithmIdentifier;

public class MessageImprint {
	/*-
	 * MessageImprint ::= SEQUENCE  {
	 *      hashAlgorithm                AlgorithmIdentifier,
	 *      hashedMessage                OCTET STRING  }
	 */
	private AlgorithmIdentifier hashAlgorithm;
	private byte[] hashedMessage;

	public MessageImprint(AlgorithmIdentifier hashAlgorithm, byte[] hashedMessage) {
		this.hashAlgorithm = hashAlgorithm;
		this.hashedMessage = hashedMessage;
	}

	public MessageImprint(String messageImprintAlgOID,
			byte[] messageImprintDigest) throws IOException {
		this.hashAlgorithm = new AlgorithmIdentifier(messageImprintAlgOID);
		this.hashedMessage = messageImprintDigest;
	}

	public AlgorithmIdentifier getHashAlgorithm() {
		return hashAlgorithm;
	}

	public byte[] getHashedMessage() {
		return hashedMessage;
	}
}
