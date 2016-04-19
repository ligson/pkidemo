package security.tsp.ms;

/**
 * 
 * Time Stamp Request
 * 
 * The time stamp request is sent within an HTTP 1.1 POST message. In the HTTP
 * header, the CacheControl directive is set to no-cache, and the Content-Type
 * directive is set to application/octet-stream. The body of the HTTP message is
 * a base64 encoding of Distinguished Encoding Rules (DER) encoding of the time
 * stamp request.
 * 
 * Although not currently used, the Content-Length directive should also be used
 * in constructing the HTTP message because it helps the time stamp server
 * locate where the request is within the HTTP POST.
 * 
 * Other HTTP headers may also be present and should be ignored if they are not
 * understood by the requestor or time stamp server.
 * 
 * The time stamp request is an ASN.1 encoded message. The format of the request
 * is as follows.
 * 
 * <pre>
 * CopyTimeStampRequest ::= SEQUENCE {
 *    countersignatureType OBJECT IDENTIFIER,
 *    attributes Attributes OPTIONAL, 
 *    content  ContentInfo
 * }
 * </pre>
 * 
 * The countersignatureType is the object identifier (OID) that identifies this
 * as a time stamp countersignature and should be the exact OID
 * 1.3.6.1.4.1.311.3.2.1.
 * 
 * No attributes are currently included in the time stamp request.
 * 
 * The content is a ContentInfo as defined by PKCS #7. The content is the data
 * to be signed. For signature time stamping, the ContentType should be Data,
 * and the content should be the encryptedDigest (signature) from the SignerInfo
 * of the PKCS #7 content to be time stamped.
 * 
 * @author ShiningWang
 * http://msdn.microsoft.com/en-us/library/bb931395(v=vs.85).aspx
 */
public class MSTSPReauest {

}
