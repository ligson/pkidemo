package security.tsp;

import java.io.IOException;

import security.util.ObjectIdentifier;


public class TSAPolicyId extends ObjectIdentifier {
	private static final long serialVersionUID = 4603145878834047830L;

	public TSAPolicyId(String identifier) throws IOException {
		super(identifier);
	}

}
