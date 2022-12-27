package de.hechler.decryptdownloader;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.util.ArmoredOutputStreamFactory;
import org.pgpainless.util.Passphrase;

import de.hechler.decryptdownloader.utils.ChecksumInputStream;
import de.hechler.decryptdownloader.utils.ChecksumOutputStream;

public class EncrypterWithPW {

	private String password;
	
	public static class EncryptResult {
		public long sourceFilesize;
		public String sourceSHA256;
		public long targetFilesize;
		public String targetSHA256;
		public EncryptResult(long sourceFilesize, String sourceSHA256, long targetFilesize, String targetSHA256) {
			this.sourceFilesize = sourceFilesize;
			this.sourceSHA256 = sourceSHA256;
			this.targetFilesize = targetFilesize;
			this.targetSHA256 = targetSHA256;
		}
		@Override
		public String toString() {
			return "{\"sourceFilesize\":" + sourceFilesize + ",\"sourceSHA256\":\"" + sourceSHA256
					+ "\",\"targetFilesize\":" + targetFilesize + ",\"targetSHA256\":\"" + targetSHA256 + "\"}";
		}
		
	}
	
	public EncrypterWithPW(String password) {
		this.password = password;
	}

	public EncryptResult encrypt(Path inputFilename, Path outputFilename) {
		return encrypt(inputFilename, outputFilename, null);
	}
	public EncryptResult encrypt(Path inputFilename, Path outputFilename, String comment) {
		try {
			try (InputStream in = new FileInputStream(inputFilename.toFile())) {
				try (OutputStream out = new FileOutputStream(outputFilename.toFile())) {
					return encrypt(in, out, comment);
				}
			}
		} catch (Exception e) {
			throw new RuntimeException(e.toString(), e);
		}
		
	}

	
	public EncryptResult encrypt(InputStream plaintextInputStream, OutputStream outputStream) {
		return encrypt(plaintextInputStream, outputStream, null);
	}
	public EncryptResult encrypt(InputStream plaintextInputStream, OutputStream outputStream, String comment) {
		try {
			ChecksumInputStream cin = new ChecksumInputStream("SHA-256", plaintextInputStream);
			ChecksumOutputStream cout = new ChecksumOutputStream("SHA-256", outputStream);
			
			if (comment != null) {
				ArmoredOutputStreamFactory.setComment(comment);
			}
			
	        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
	                .onOutputStream(cout)
	                .withOptions(
	                        ProducerOptions.encrypt(
	                        		new EncryptionOptions()
	                                        .addPassphrase(Passphrase.fromPassword(password))
	                                        // optionally override symmetric encryption algorithm
	                                        .overrideEncryptionAlgorithm(SymmetricKeyAlgorithm.AES_256)
	                        ).setAsciiArmor(true) // Ascii armor or not
	                        // .setComment("Comment was set in Options.")
	                );
	
	        Streams.pipeAll(cin, encryptionStream);
	        encryptionStream.close();
	        long sourceFilesize = cin.getSize();
	        String sourceSHA256 = cin.getMD();
	        long targetFilesize = cout.getSize();
	        String targetSHA256 = cout.getMD();
	        return new EncryptResult(sourceFilesize, sourceSHA256, targetFilesize, targetSHA256);
	        // Information about the encryption (algorithms, detached signatures etc.)
//	        EncryptionResult result = encryptionStream.getResult();
//	        System.out.println(result.getEncryptionAlgorithm());
		} catch (IOException | PGPException e) {
			throw new RuntimeException(e.toString(), e);
		}

	}
	
}
