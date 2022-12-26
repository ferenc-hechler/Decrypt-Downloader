package de.hechler.pgpencrypter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import de.hechler.pgpencrypter.encrypt.EncrypterWithPW;

class EncrypterWithPWTest {

	private static final String TESTDATA_FOLDER = "./testdata"; 
	
	@Test
	void testEncrypterWithPW() throws IOException {
		Path inputFile = Paths.get(TESTDATA_FOLDER).resolve("input/testdatei.txt");
		String password = "Geheim";
		Path outputFile = Paths.get(TESTDATA_FOLDER).resolve("output/testdatei-withpw.txt.pgp");
		Files.createDirectories(outputFile.getParent());
		EncrypterWithPW enc = new EncrypterWithPW(password);
		enc.encrypt(inputFile, outputFile);
	}
	
	@Test
	void testEncrypterWithPW2() throws IOException {
		Path inputFile = Paths.get(TESTDATA_FOLDER).resolve("input/testdatei.txt");
		String password = "abc-579";
		Path outputFile = Paths.get(TESTDATA_FOLDER).resolve("output/test.txt.pgp");
		Files.createDirectories(outputFile.getParent());
		EncrypterWithPW enc = new EncrypterWithPW(password);
		enc.encrypt(inputFile, outputFile);
	}
	
//	@Test
	void testMCEncrypterWithPW() throws IOException {
		Path inputFile = Paths.get(TESTDATA_FOLDER).resolve("D:\\VSERVER\\CONTABO_MINECRAFT_PATMCS\\home\\patrick\\BACKUP\\backup_MCS_20221226_210651.tgz");
		String password = "abc-579";
		Path outputFile = Paths.get(TESTDATA_FOLDER).resolve("output/backup_MCS_20221226_210651.tgz.pgp");
		Files.createDirectories(outputFile.getParent());
		EncrypterWithPW enc = new EncrypterWithPW(password);
		enc.encrypt(inputFile, outputFile);
	}
	
}
