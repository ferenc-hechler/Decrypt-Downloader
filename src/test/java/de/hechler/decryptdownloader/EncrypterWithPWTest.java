package de.hechler.decryptdownloader;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import de.hechler.decryptdownloader.EncrypterWithPW;
import de.hechler.decryptdownloader.EncrypterWithPW.EncryptResult;

class EncrypterWithPWTest {

	private static final String TESTDATA_FOLDER = "./testdata"; 
	
	@Test
	void testEncrypterWithPW2() throws IOException {
		Path inputFile = Paths.get(TESTDATA_FOLDER).resolve("input/testdatei.txt");
		String password = "abc-123";
		Path outputFile = Paths.get(TESTDATA_FOLDER).resolve("output/testdatei.txt.pgp");
		Files.createDirectories(outputFile.getParent());
		EncrypterWithPW enc = new EncrypterWithPW(password);
		EncryptResult hashes = enc.encrypt(inputFile, outputFile, "JUnit Test");
		System.out.println(hashes);
		assertEquals(hashes.sourceFilesize, 126);
		assertEquals(hashes.sourceSHA256, "0e69b9a1b2efdfc98600f20ffe7721a499d2deab3cf464e6fb328e51293b7a49");
		// can targetFilesize differ? targetSHA256 is always different.  
		assertEquals(hashes.targetFilesize, 345);
	}
	
}
