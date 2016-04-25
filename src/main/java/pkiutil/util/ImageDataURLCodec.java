package pkiutil.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

import org.bouncycastle.util.encoders.Base64;
/**
 * 
 *@author wang_xuanmin
 *@Deprecated 被DataURLCodec取代
 */

@Deprecated
public class ImageDataURLCodec {
	private static final String protocol = "data";
	private static final String mediatype = "image";
	private static final String codec = "base64";

	public static String encode(byte[] imageBuffer) throws IOException {
		String base64Buffer = new String(Base64.encode(imageBuffer));
		ByteArrayInputStream bais = new ByteArrayInputStream(imageBuffer);
		ImageInputStream iis = ImageIO.createImageInputStream(bais);
		Iterator<ImageReader> iter = ImageIO.getImageReaders(iis);
		iis.close();
		if (!iter.hasNext()) { throw new IOException("No image file found."); }
		ImageReader reader = iter.next();
		String imageType = reader.getFormatName();
		String dataURL = protocol + ":" + mediatype + "/" + imageType + ";" + codec + "," + base64Buffer;
		return dataURL;
	}

	public static byte[] decode(String dataURL) {
		String regex = "data:[ ]*image/[^;]+;[ ]*base64 *,.*";
		if (dataURL.matches(regex)) { return Base64.decode(dataURL.substring(dataURL.lastIndexOf(","), dataURL.length()).trim()); }
		return null;
	}
}
