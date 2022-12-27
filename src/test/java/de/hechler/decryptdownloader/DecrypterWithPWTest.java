package de.hechler.decryptdownloader;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import de.hechler.decryptdownloader.DecrypterWithPW;
import de.hechler.decryptdownloader.DecrypterWithPW.DecryptResult;

class DecrypterWithPWTest {

	private static final String TESTDATA_FOLDER = "./testdata"; 
	
	@Test
	void testDecrypterWithPW() throws IOException {
		Path inputFile = Paths.get(TESTDATA_FOLDER).resolve("input/testdatei.txt.pgp");
		String password = "abc-123";
		Path outputFile = Paths.get(TESTDATA_FOLDER).resolve("output/testdatei.txt");
		Files.createDirectories(outputFile.getParent());
		DecrypterWithPW dec = new DecrypterWithPW(password);
		DecryptResult hashes = dec.decrypt(inputFile, outputFile);
		System.out.println(hashes);
		assertEquals(hashes.sourceFilesize, 515);
		assertEquals(hashes.targetFilesize, 126);
		assertEquals(hashes.targetSHA256, "0e69b9a1b2efdfc98600f20ffe7721a499d2deab3cf464e6fb328e51293b7a49");
	}

}
