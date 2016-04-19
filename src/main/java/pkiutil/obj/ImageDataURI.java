package pkiutil.obj;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

import pkiutil.web.DataURLCodec;

public class ImageDataURI {
	private byte[] buffer;
	private byte[] hashcode;
	private String hashalg;
	private String imagetype;
	private HashMap<String, String> params;

	public ImageDataURI(URL url) throws IOException {
		this(url.openStream());
	}

	public ImageDataURI(File file) throws IOException {
		this(new FileInputStream(file));
	}

	public ImageDataURI(InputStream in) throws IOException {
		byte[] buf = new byte[in.available()];
		in.read(buf);
		in.close();
		init(buf);
	}

	public ImageDataURI(String filepath) throws IOException {
		this(new FileInputStream(filepath));
	}

	public ImageDataURI(byte[] buffer) throws IOException {
		init(buffer);
	}

	private void init(byte[] buf) throws IOException {
		this.buffer = buf;
		this.hashalg = "SHA1";
		try {
			MessageDigest md = MessageDigest.getInstance(hashalg);
			md.update(buffer);
			this.hashcode = md.digest();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		ByteArrayInputStream bais = new ByteArrayInputStream(this.buffer);
		ImageInputStream iis = ImageIO.createImageInputStream(bais);
		Iterator<ImageReader> iter = ImageIO.getImageReaders(iis);
		iis.close();
		bais.close();
		if (!iter.hasNext()) { throw new IOException("No image file found."); }
		ImageReader reader = iter.next();
		this.imagetype = reader.getFormatName();
	}

	public byte[] getBuffer() {
		return buffer;
	}

	public byte[] getHashcode() {
		return hashcode;
	}

	public String getHashalg() {
		return hashalg;
	}

	public String getMediatype() {
		return imagetype;
	}

	public void addAllParams(Map<String, String> params) {
		if (!checkParams()) this.params = new HashMap<String, String>(params);
		else this.params.putAll(params);
	}

	public void addParams(String key, String value) {
		if (!checkParams()) this.params = new HashMap<String, String>();
		this.params.put(key, value);
	}

	public void clearParams() {
		if (checkParams()) this.params.clear();
	}

	public String getDataUrl() throws IOException {
		StringWriter writer = new StringWriter();
		DataURLCodec.encode(buffer, writer, "image/"+imagetype, params);
		writer.flush();
		return writer.toString();
	}

	private boolean checkParams() {
		return this.params != null;
	}


}
