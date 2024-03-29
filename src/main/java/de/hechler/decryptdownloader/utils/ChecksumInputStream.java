package de.hechler.decryptdownloader.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ChecksumInputStream extends InputStream {
	
	private InputStream delegte;
	private MessageDigest md;
	private long size;

	public ChecksumInputStream(String algorithm, InputStream delegte) {
		this.delegte = delegte;
		try {
			this.md = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.toString());
		}
		this.size = 0;
	}

	public String getMD() {
		byte[] bytes = md.digest();
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
	}

	public long getSize() {
		return size;
	}
	
	public int read() throws IOException {
		int result = delegte.read();
		if (result != -1) {
			md.update((byte)result);
			size += 1;
		}
		return result;
	}

	public int read(byte[] b) throws IOException {
		int result = delegte.read(b);
		if (result > 0) {
			md.update(b, 0, result);
			size += result;
		}
		return result;
	}

	public int read(byte[] b, int off, int len) throws IOException {
		int result = delegte.read(b, off, len);
		if (result > 0) {
			md.update(b, off, result);
			size += result;
		}
		return result;
	}

	public int available() throws IOException {
		return delegte.available();
	}

	public void close() throws IOException {
		delegte.close();
	}

	public long skip(long n) throws IOException {
		throw new UnsupportedOperationException("skip not allowed in ChecksumInputStream");
	}

	public void mark(int readlimit) {
		throw new UnsupportedOperationException("mark not allowed in ChecksumInputStream");
	}

	public void reset() throws IOException {
		throw new UnsupportedOperationException("reset not allowed in ChecksumInputStream");
	}

	public boolean markSupported() {
		return false;
	}


}
