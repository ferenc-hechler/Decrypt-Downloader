package de.hechler.pgpencrypter.decrypt;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.util.Passphrase;

import de.hechler.pgpencrypter.utils.ChecksumInputStream;
import de.hechler.pgpencrypter.utils.ChecksumOutputStream;

public class DecrypterWithPW {

	private String password;
	
	public static class DecryptResult {
		public long sourceFilesize;
		public String sourceSHA256;
		public long targetFilesize;
		public String targetSHA256;
		public DecryptResult(long sourceFilesize, String sourceSHA256, long targetFilesize, String targetSHA256) {
			this.sourceFilesize = sourceFilesize;
			this.sourceSHA256 = sourceSHA256;
			this.targetFilesize = targetFilesize;
			this.targetSHA256 = targetSHA256;
		}
		@Override
		public String toString() {
			return "DecryptResult [sourceFilesize=" + sourceFilesize + ", sourceSHA256=" + sourceSHA256
					+ ", targetFilesize=" + targetFilesize + ", targetSHA256=" + targetSHA256 + "]";
		}
		
	}
	
	public DecrypterWithPW(String password) {
		this.password = password;
	}

	public DecryptResult decrypt(Path inputFilename, Path outputFilename) {
		try {
			try (InputStream in = new FileInputStream(inputFilename.toFile())) {
				try (OutputStream out = new FileOutputStream(outputFilename.toFile())) {
					return decrypt(in, out);
				}
			}
		} catch (Exception e) {
			throw new RuntimeException(e.toString(), e);
		}
		
	}

	
	public DecryptResult decrypt(InputStream encryptedInputStream, OutputStream outputStream) {
		try {
			ChecksumInputStream cin = new ChecksumInputStream("SHA-256", encryptedInputStream);
			ChecksumOutputStream cout = new ChecksumOutputStream("SHA-256", outputStream);
			
	        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
	                .onInputStream(cin)
	                .withOptions(
	                		new ConsumerOptions()
                            .addDecryptionPassphrase(Passphrase.fromPassword(password))
	                );
	
	        Streams.pipeAll(decryptionStream, cout);
	        decryptionStream.close();
	        long sourceFilesize = cin.getSize();
	        String sourceSHA256 = cin.getMD();
	        long targetFilesize = cout.getSize();
	        String targetSHA256 = cout.getMD();
	        return new DecryptResult(sourceFilesize, sourceSHA256, targetFilesize, targetSHA256);
	        // Information about the encryption (algorithms, detached signatures etc.)
//	        EncryptionResult result = encryptionStream.getResult();
//	        System.out.println(result.getEncryptionAlgorithm());
		} catch (IOException | PGPException e) {
			throw new RuntimeException(e.toString(), e);
		}

	}
	
}
