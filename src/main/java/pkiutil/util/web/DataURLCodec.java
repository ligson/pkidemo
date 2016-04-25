package pkiutil.util.web;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.AccessController;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;

import org.bouncycastle.util.encoders.Base64;

import pkiutil.util.action.GetPropertyAction;

public class DataURLCodec {
	private static HashMap<String, String> imageTypes = new HashMap<String, String>();
	private static HashMap<String, String> textTypes = new HashMap<String, String>();
	private static boolean verbose = false;

	public static boolean getVerbose() {
		return verbose;
	}

	public static void setVerbose(boolean newVerbose) {
		verbose = newVerbose;
	}

	public static void encode(File file, Writer out, String mimeType, Map<String, String> params) throws MalformedURLException, IOException {
		encode(file.toURL(), out, mimeType, params);
	}

	public static void encode(URL url, Writer out, String mimeType, Map<String, String> params) throws IOException {
		URLConnection conn = url.openConnection();
		if (mimeType == null)
			mimeType = getMimeType(url.getFile(), conn.getContentType());
		if (verbose) {
			System.err.println("[INFO] No MIME type provided, using detected type of '" + mimeType + "'.");
		}

		InputStream in = conn.getInputStream();
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		int c;
		while ((c = in.read()) != -1) {
			byteStream.write(c);
		}

		byteStream.flush();
		in.close();

		encode(byteStream.toByteArray(), out, mimeType, params);
	}

	public static void encode(byte[] dataBuffer, Writer out, String mimeType, Map<String, String> params) throws IOException {
		/*
		 * dataurl := "data:" [ mediatype ] [ ";base64" ] "," data
		 * 
		 * mediatype := [ type "/" subtype ] *( ";" parameter )
		 * 
		 * data := *urlchar
		 * 
		 * parameter := attribute "=" value
		 */
		mimeType = mimeType.trim();
		if (!mimeType.matches("^([x|X]-){0,1}\\w+/([x|X]-){0,1}\\w+$")) {
			throw new RuntimeException("error mime type " + mimeType);
		}
		String data = new String(Base64.encode(dataBuffer));
		StringBuilder strbuilder = new StringBuilder();
		strbuilder.append("data:");
		strbuilder.append(mimeType);
		if (params != null) {
			Iterator<String> it = params.keySet().iterator();
			String attribute, value;
			while (it.hasNext()) {
				attribute = it.next().trim();
				if (attribute.matches(".*[ |(|)|<|>|@|,|;|:|\\\\|\"|/|\\[|\\]|?|=].*")) {
					throw new RuntimeException("error parameter attribute");
				}
				value = replaceAttributeValue(params.get(attribute), ENCODE);
				strbuilder.append(";").append(attribute).append('=').append(value);
			}
		}
		strbuilder.append(";base64");
		strbuilder.append(",");
		strbuilder.append(data);
		String dataURL = strbuilder.toString();
		out.write(dataURL);
	}

	public static Map<String, Object> decodeAll(String dataURL) {
		if (dataURL == null) {
			return null;
		}
		Map<String, Object> ret = new HashMap<String, Object>();
		StringTokenizer tokenizer = new StringTokenizer(dataURL);
		tokenizer.hasMoreTokens();
		// TODO 未完成
		return ret;
	}
	/**
	 * decode image dataurl only
	 * @param dataURL
	 * @return
	 */
	@Deprecated
	public static byte[] decode(String dataURL) {
		String regex = "^data: *image/[^;]+;.*base64 *,.*$";
		if (dataURL.trim().matches(regex)) {
			return Base64.decode(dataURL.substring(dataURL.lastIndexOf(","), dataURL.length()).trim());
		}
		return null;
	}

	private static final int ENCODE = 1;
	private static final int DECODE = 2;

	@SuppressWarnings("unchecked")
	private static String replaceAttributeValue(String str, int mode) {
		str = str.trim();
		String dfltEncName = (String) AccessController.doPrivileged(new GetPropertyAction("file.encoding"));
		switch (mode) {
		case ENCODE:
			try {
				return URLEncoder.encode(str, dfltEncName);
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			break;
		// if (str.matches(".*[ |(|)|<|>|@|,|;|:|\\\\|\"|/|\\[|\\]|?|=].*"))
		// return '"' + str.replaceAll("\\\\", "\\\\\\\\").replaceAll("\"",
		// "\\\\\"") + '"';
		case DECODE:
			try {
				return URLDecoder.decode(str, dfltEncName);
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
			break;
		// if (str.matches("^\".*\"$"))
		// return str.substring(1, str.length() - 1).replaceAll("\\\\\"",
		// "\"").replaceAll("\\\\\\\\", "\\\\");
		}
		return str;
	}

	private static String getFileType(String filename) {
		String type = "";

		int idx = filename.lastIndexOf('.');
		if ((idx >= 0) && (idx < filename.length() - 1)) {
			type = filename.substring(idx + 1);
		}

		return type;
	}

	private static String getMimeType(String filename, String mimeType) throws IOException {
		if (mimeType == null) {
			String type = getFileType(filename);

			if (imageTypes.containsKey(type))
				mimeType = (String) imageTypes.get(type);
			else if (textTypes.containsKey(type))
				// if no charset assigned, default US-ASCII [RFC 2045]
				mimeType = (String) textTypes.get(type);// + ";charset=UTF-8";
			else {
				throw new IOException("No MIME type provided and MIME type couldn't be automatically determined.");
			}

			if (verbose) {
				System.err.println("[INFO] No MIME type provided, defaulting to '" + mimeType + "'.");
			}
		}

		return mimeType;
	}

	static {
		imageTypes.put("gif", "image/gif");
		imageTypes.put("jpg", "image/jpeg");
		imageTypes.put("png", "image/png");
		imageTypes.put("jpeg", "image/jpeg");

		textTypes.put("htm", "text/html");
		textTypes.put("html", "text/html");
		textTypes.put("xml", "application/xml");
		textTypes.put("xhtml", "application/xhtml+xml");
		textTypes.put("js", "application/x-javascript");
		textTypes.put("css", "text/css");
		textTypes.put("txt", "text/plain");
	}

}