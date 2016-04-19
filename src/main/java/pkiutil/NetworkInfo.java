package pkiutil;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.text.ParseException;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class NetworkInfo {
	public final static String getMacAddress() throws IOException {
		String os = System.getProperty("os.name");

		try {
			if (os.startsWith("Windows")) {
				return parseMacAddress(windowsRunIpConfigCommand());
			} else if (os.startsWith("Linux")) {
				return parseMacAddress(linuxRunIfConfigCommand());
			} else {
				throw new IOException("unknown operating system: " + os);
			}
		} catch (ParseException ex) {
			ex.printStackTrace();
			throw new IOException(ex.getMessage());
		}
	}

	private final static String linuxRunIfConfigCommand() throws IOException {
		Process p = Runtime.getRuntime().exec("ifconfig");
		InputStream stdoutStream = new BufferedInputStream(p.getInputStream());
		StringBuffer buffer = new StringBuffer();
		for (;;) {
			int c = stdoutStream.read();
			if (c == -1) break;
			buffer.append((char) c);
		}
		String outputText = buffer.toString();
		stdoutStream.close();
		return outputText;
	}

	/*
	 * Windows stuff
	 */
	private final static String parseMacAddress(String ipConfigResponse) throws ParseException {
		String localHost = null;
		try {
			localHost = InetAddress.getLocalHost().getHostAddress();
		} catch (java.net.UnknownHostException ex) {
			ex.printStackTrace();
			throw new ParseException(ex.getMessage(), 0);
		}

		StringTokenizer tokenizer = new StringTokenizer(ipConfigResponse, "\n");
		String firstMacAddress = null;

		while (tokenizer.hasMoreTokens()) {
			String line = tokenizer.nextToken().trim();
			firstMacAddress = getMacAddress(line);
			if (firstMacAddress != null) {
				break;
			}
		}
		if (firstMacAddress == null) throw new ParseException("cannot read MAC address for " + localHost + " from [" + ipConfigResponse + "]", 0);
		return firstMacAddress.replaceAll("[:|-]", "");
	}

	private final static String getMacAddress(String line) {
		String regex = "[0-9|A-F|a-f]{2}([-|:][0-9|A-F|a-f]{2}){5}";
		Pattern p = Pattern.compile(regex);
		Matcher match = p.matcher(line);
		if (match.find()) { return match.group(); }
		return null;
	}

	private final static String windowsRunIpConfigCommand() throws IOException {
		Process p = Runtime.getRuntime().exec("ipconfig /all");
		InputStream stdoutStream = new BufferedInputStream(p.getInputStream());
		StringBuffer buffer = new StringBuffer();
		for (;;) {
			int c = stdoutStream.read();
			if (c == -1) break;
			buffer.append((char) c);
		}
		String outputText = buffer.toString();
		stdoutStream.close();
		return outputText;
	}
}
