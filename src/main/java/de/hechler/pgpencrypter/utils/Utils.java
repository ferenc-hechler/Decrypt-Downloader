package de.hechler.pgpencrypter.utils;

public class Utils {

	
	public static String bytes2hex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes) {
		    result.append(String.format("%02x", b));
		}
		return result.toString();
	}


}
