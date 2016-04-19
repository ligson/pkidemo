package security.tsp;

import java.io.IOException;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TSPException;

public class TimeStampToken extends org.bouncycastle.tsp.TimeStampToken{

	public TimeStampToken(ContentInfo contentInfo) throws TSPException,
			IOException {
		super(contentInfo);
	}
	
}
