package security.tsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import asn1.DERUTF8String;
import security.pkix.PKIFailureInfo;
import security.pkix.PKIFreeText;
import security.pkix.PKIStatus;
import security.pkix.PKIStatusInfo;


public class TimeStampResp {
	/*-
	 * TimeStampResp ::= SEQUENCE  {
	 *   status                  PKIStatusInfo,
	 *   timeStampToken          TimeStampToken     OPTIONAL  }
	 */
	private PKIStatusInfo status;
	private TimeStampToken timeStampToken;

	public TimeStampResp(PKIStatusInfo status, TimeStampToken timeStampToken) {
		this.status = status;
		this.timeStampToken = timeStampToken;
	}

	public PKIStatusInfo getStatus() {
		return status;
	}

	public TimeStampToken getTimeStampToken() {
		return timeStampToken;
	}

	public byte[] getEncoded() throws IOException, TSPException {
		org.bouncycastle.tsp.TimeStampResponse bcresp = null;
		try {
			org.bouncycastle.asn1.cmp.PKIFreeText freeText = null;
			if(this.status.getStatusString()!=null){
				String[] strings = new String[this.status.getStatusString().size()];
				for (int i = 0; i < strings.length; i++) {
					DERUTF8String derUTF8String = this.status.getStatusString()
					.getStringAt(i);
					strings[i] = derUTF8String.getString();
				}
				freeText = new org.bouncycastle.asn1.cmp.PKIFreeText(strings);
			}
			org.bouncycastle.asn1.cmp.PKIFailureInfo failureInfo = null;
			if(this.status.getFailInfo()!=null)
				failureInfo = new org.bouncycastle.asn1.cmp.PKIFailureInfo(
						new org.bouncycastle.asn1.DERBitString(
								this.status.getFailInfo().getDEREncoded()));

			bcresp = new org.bouncycastle.tsp.TimeStampResponse(
					new org.bouncycastle.asn1.tsp.TimeStampResp(
							new org.bouncycastle.asn1.cmp.PKIStatusInfo(
									this.status.getStatus().getValue()
									.intValue(),
									freeText,failureInfo
							),
							timeStampToken.toCMSSignedData().getContentInfo()));
			return bcresp.getEncoded();
		} catch (org.bouncycastle.tsp.TSPException e) {
			throw new TSPException(e.getMessage(), e);
		}
	}

	public static TimeStampResp getInstance(byte[] bytes) throws IOException,
	TSPException {
		return getInstance(new ByteArrayInputStream(bytes));
	}

	public static TimeStampResp getInstance(InputStream in) throws IOException,TSPException {
		TimeStampResp req = null;
		org.bouncycastle.asn1.tsp.TimeStampResp bcresp = org.bouncycastle.asn1.tsp.TimeStampResp
		.getInstance(new org.bouncycastle.asn1.ASN1InputStream(in)
		.readObject());
		try {
			PKIFreeText freeText = null;
			if(bcresp.getStatus().getStatusString()!=null){
				String[] strings = new String[bcresp.getStatus().getStatusString()
				                              .size()];
				for (int i = 0; i < strings.length; i++) {
					org.bouncycastle.asn1.DERUTF8String derUTF8String = bcresp
					.getStatus().getStatusString().getStringAt(i);
					strings[i] = derUTF8String.getString();
				}
				freeText = new PKIFreeText(strings);
			}
			PKIFailureInfo failureInfo = null;
			if(bcresp.getStatus().getFailInfo()!=null)
				failureInfo  = new PKIFailureInfo(bcresp.getStatus().getFailInfo()
						.intValue());
			req = new TimeStampResp(new PKIStatusInfo(new PKIStatus(bcresp
					.getStatus().getStatus()),freeText ,failureInfo)
			, new TimeStampToken(
					bcresp.getTimeStampToken()));
		} catch (org.bouncycastle.tsp.TSPException e) {
			throw new TSPException(e.getMessage(), e);
		}

		return req;
	}
}
