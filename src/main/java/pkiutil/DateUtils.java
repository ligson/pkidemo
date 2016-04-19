package pkiutil;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class DateUtils {
	public static String shortFormat = "yyyyMMdd";

	public static String longFormat = "yyyyMMddHHmmss";

	public static String webFormat = "yyyy-MM-dd";

	public static String timeFormat = "HHmmss";

	public static String monthFormat = "yyyyMM";

	public static String chineseDtFormat = "yyyy��MM��dd��";

	public static String newFormat = "yyyy-MM-dd HH:mm:ss";

	/***************************************************************************
	 * ��ʽ�����ڣ����ָ�����ַ��ʽ
	 * 
	 * <pre>
	 * ��ĸ  ���ڻ�ʱ��Ԫ��  ��ʾ  ʾ��  
	 * G  Era ��־��  Text  AD  
	 * y  ��  Year  1996; 96  
	 * M  ���е��·�  Month  July; Jul; 07  
	 * w  ���е�����  Number  27  
	 * W  �·��е�����  Number  2  
	 * D  ���е�����  Number  189  
	 * d  �·��е�����  Number  10  
	 * F  �·��е�����  Number  2  
	 * E  �����е�����  Text  Tuesday; Tue  
	 * a  Am/pm ���  Text  PM  
	 * H  һ���е�Сʱ��0-23��  Number  0  
	 * k  һ���е�Сʱ��1-24��  Number  24  
	 * K  am/pm �е�Сʱ��0-11��  Number  0  
	 * h  am/pm �е�Сʱ��1-12��  Number  12  
	 * m  Сʱ�еķ�����  Number  30  
	 * s  �����е�����  Number  55  
	 * S  ������  Number  978  
	 * z  ʱ��  General time zone  Pacific Standard Time; PST; GMT-08:00  
	 * Z  ʱ��  RFC 822 time zone  -0800
	 * </pre>
	 * 
	 * @param date
	 * @param format
	 * @return
	 */
	public static String getCustomDateString(Date date, String format) {
		if (date == null)
			return null;
		DateFormat dateFormat = new SimpleDateFormat(format);
		return dateFormat.format(date);
	}

	/***
	 * ���ָ�������ڸ�ʽString����Date����
	 * @param sDate
	 * @param format
	 * @return
	 */
	public static Date parseCustomDateString(String sDate, String format) {
		DateFormat dateFormat = new SimpleDateFormat(format);
		Date d = null;

		if ((sDate != null) && (sDate.length() == format.length())) {
			try {
				d = dateFormat.parse(sDate);
			} catch (ParseException ex) {
				return null;
			}
		}

		return d;
	}

	/**
	 * ���yyyyMMddHHmmss���ڸ�ʽString����Date����
	 * 
	 * @param sDate
	 * @return Date
	 */
	public static Date parseDateLongFormat(String sDate) {
		DateFormat dateFormat = new SimpleDateFormat(longFormat);
		Date d = null;

		if ((sDate != null) && (sDate.length() == longFormat.length())) {
			try {
				d = dateFormat.parse(sDate);
			} catch (ParseException ex) {
				return null;
			}
		}

		return d;
	}

	/**
	 * ���Date���󷵻�yyyyMMddHHmmss���ڸ�ʽString
	 * 
	 * @param date
	 * @return String
	 */
	public static String getLongDateString(Date date) {
		return getLongDateString(date, TimeZone.getDefault());
	}
	
	/**
	 * ���Date���󷵻�yyyyMMddHHmmss���ڸ�ʽString
	 * 
	 * @param date
	 * @TimeZone zone ʱ�� eg:TimeZone.getTimeZone("GMT")
	 * @return String
	 */
	public static String getLongDateString(Date date, TimeZone zone) {
		if (date == null)
			return null;
		DateFormat dateFormat = new SimpleDateFormat(longFormat);
		dateFormat.setTimeZone(zone);
		return dateFormat.format(date);
	}
}
