package de.hechler.decryptdownloader.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;

public class Utils {

	
	public static String bytes2hex(byte[] bytes) {
		StringBuilder result = new StringBuilder();
		for (byte b : bytes) {
		    result.append(String.format("%02x", b));
		}
		return result.toString();
	}

	public static String calcFileSHA256(Path inputFile) {
		try {
			ChecksumInputStream cin = new ChecksumInputStream("SHA-256", new FileInputStream(inputFile.toFile()));
			byte[] buf = new byte[32768];
			cin.read(buf);
			return cin.getMD();
		} catch (IOException e) {
			throw new RuntimeException(e.toString(), e);
		}
	}


}
