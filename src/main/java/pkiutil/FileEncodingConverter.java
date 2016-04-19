package pkiutil;

import java.io.*;

public class FileEncodingConverter {
	// Java file extention
	public static final String FILE_EXTENTION_JAVA = ".java";

	public static final int BUFFER_SIZE = 1024 * 4;

	// File encoding
	public static final String FILE_ENCODING_UTF8 = "UTF_8";
	public static final String FILE_ENCODING_GBK = "GBK";
	public static final String FILE_ENCODING_GB2312 = "gb2312";

	/**
	 * File filter, only directory and java file
	 */
	private static FileFilter fileFilter = new FileFilter() {
		public boolean accept(File file) {
			// directory and java file
			return file.isDirectory() || (file.isFile() && file.getName().endsWith(FILE_EXTENTION_JAVA));
		}
	};

	public static void scanDirectory(String sourceDirectoryPath, String destDirectoryPath, String sourceFileEncoding, String destFileEncoding) {
		File destDirectory = new File(destDirectoryPath);
		if (!destDirectory.exists()) {
			destDirectory.mkdir();
		}

		File sourceDirectory = new File(sourceDirectoryPath);

		scanDirectory(sourceDirectory, sourceDirectoryPath, destDirectoryPath, sourceFileEncoding, destFileEncoding);
	}

	private static void scanDirectory(File directory, String sourceDirectoryPath, String destDirectoryPath, String sourceFileEncoding, String destFileEncoding) {
		File[] files = directory.listFiles(fileFilter);

		File destFile;
		for (File file : files) {
			if (file.isDirectory()) {
				destFile = new File(destDirectoryPath + file.getAbsolutePath().substring(sourceDirectoryPath.length()));
				if (!destFile.exists()) {
					destFile.mkdir();
				}

				scanDirectory(file, sourceDirectoryPath, destDirectoryPath, sourceFileEncoding, destFileEncoding);
			} else {
				System.out.println("Source file：\t" + file.getAbsolutePath() + "\nDest file：\t" + (destDirectoryPath + file.getAbsolutePath().substring(sourceDirectoryPath.length())) + "\n-----------------------------------------------------------------");

				convertFile(file.getAbsolutePath(), destDirectoryPath + file.getAbsolutePath().substring(sourceDirectoryPath.length()), sourceFileEncoding, destFileEncoding);
			}
		}
	}

	/**
	 * @param sourceFilePath
	 *            sourceFilePath
	 * @param destFilePath
	 *            destFilePath
	 * @param sourceFileEncoding
	 *            sourceFileEncoding
	 * @param destFileEncoding
	 *            destFileEncoding
	 */
	private static void convertFile(String sourceFilePath, String destFilePath, String sourceFileEncoding, String destFileEncoding) {
		InputStream in = System.in;
		OutputStream out = System.out;

		Reader reader = null;
		Writer writer = null;

		try {
			// set up byte streams
			if (sourceFilePath != null) {
				in = new FileInputStream(sourceFilePath);
			}

			if (destFilePath != null) {
				out = new FileOutputStream(destFilePath);
			}

			// Use default encoding if no encoding is specified.
			if (sourceFileEncoding == null) sourceFileEncoding = System.getProperty("file.encoding");
			if (destFileEncoding == null) destFileEncoding = System.getProperty("file.encoding");

			// Set up character stream
			reader = new BufferedReader(new InputStreamReader(in, sourceFileEncoding));
			writer = new BufferedWriter(new OutputStreamWriter(out, destFileEncoding));

			char[] buffer = new char[BUFFER_SIZE];
			int len;
			while ((len = reader.read(buffer)) != -1) {
				writer.write(buffer, 0, len);
			}
		} catch (Exception e) {
			e.printStackTrace();

		} finally {
			if (writer != null) {
				try {
					writer.flush();
					writer.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			try {
				in.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

			try {
				out.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}