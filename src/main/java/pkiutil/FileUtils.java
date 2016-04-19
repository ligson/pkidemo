package pkiutil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileUtils
{
  public static boolean exists(String fileName)
  {
    File file = new File(fileName);
    return file.exists();
  }

  public static byte[] readBytesFromFile(String fileName)
    throws IOException
  {
    FileInputStream fileInputStream = new FileInputStream(fileName);
    int total = fileInputStream.available();
    byte[] buffer = new byte[total];
    fileInputStream.read(buffer);
    fileInputStream.close();
    return buffer;
  }

  public static void saveBytesToFile(byte[] buffer, String fileName)
    throws IOException
  {
    FileOutputStream fileOutputStream = new FileOutputStream(fileName);
    fileOutputStream.write(buffer);
    fileOutputStream.close();
  }
}