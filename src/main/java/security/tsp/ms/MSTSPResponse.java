package security.tsp.ms;

/**
 * 
 * Time Stamp Response
 * 
 * The time stamp response is also sent within an HTTP 1.1 message. In the HTTP
 * header, the Content-Type directive is also set to application/octet-stream.
 * The body of the HTTP message is a base64 encoding of DER encoding of the time
 * stamp response.
 * 
 * The time stamp response is a PKCS #7 signed message signed by the time
 * stamper. The ContentInfo of the PKCS #7 message is identical to the
 * ContentInfo received in the time stamp. The PKCS #7 content contains the
 * signing time authenticated attribute (defined in PKCS #99, OID
 * 1.2.840.113549.9.5).
 * 
 * After Authenticode receives the time stamp from the server, Authenticode
 * incorporates the time stamp into the original PKCS #7 SignedData as a
 * countersignature. To accomplish this, the ContentInfo of the returned PKCS #7
 * SignedData is discarded, and the SignerInfo of the returned time stamp is
 * copied as a countersignature into the SignerInfo of the original PKCS #7
 * SignedData. The certificate chain of the time stamper is also copied into
 * Certificates in the original PKCS #7 SignedData as an unauthenticated
 * attribute of the original signer.
 * 
 * @author ShiningWang
 * 
 */
public class MSTSPResponse {

}
