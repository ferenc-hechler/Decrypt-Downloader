package de.hechler.pgpencrypter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import de.hechler.pgpencrypter.decrypt.DecrypterWithPW;

class DecrypterWithPWTest {

	private static final String TESTDATA_FOLDER = "./testdata"; 
	
	@Test
	void testMCDecrypterWithPW() throws IOException {
		Path inputFile = Paths.get(TESTDATA_FOLDER).resolve("input/backup_MCS_20221226_210651.tgz.pgp");
		String password = "abc-579";
		Path outputFile = Paths.get(TESTDATA_FOLDER).resolve("output/backup_MCS_20221226_210651.tgz");
		Files.createDirectories(outputFile.getParent());
		DecrypterWithPW dec = new DecrypterWithPW(password);
		dec.decrypt(inputFile, outputFile);
	}

	@Test
	void testDecrypterWithPW() throws IOException {
		Path inputFile = Paths.get(TESTDATA_FOLDER).resolve("input/testdatei-withpw.txt.pgp");
		String password = "Geheim";
		Path outputFile = Paths.get(TESTDATA_FOLDER).resolve("output/testdatei-withpw.txt");
		Files.createDirectories(outputFile.getParent());
		DecrypterWithPW dec = new DecrypterWithPW(password);
		dec.decrypt(inputFile, outputFile);
	}

}
