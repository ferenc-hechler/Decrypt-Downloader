package de.hechler.decryptdownloader;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;

import de.hechler.decryptdownloader.DecrypterWithPW.DecryptResult;
import de.hechler.decryptdownloader.EncrypterWithPW.EncryptResult;
import de.hechler.decryptdownloader.utils.SimpleCrypto;
import de.hechler.decryptdownloader.utils.Utils;

/**
 * https://gh.pgpainless.org/
 * https://github.com/pgpainless/pgpainless/blob/master/README.md
 * 
 * @author feri
 *
 */
public class DecryptDownloaderMain {

	public static void main(String[] args) {
		try {
			if (args.length == 0) {
				usage();
			}
			
			if (args[0].equals("--encrypt-password")) {
				if (args.length != 2) {
					usage();
				}
				String pwd = args[1];
				System.out.println(SimpleCrypto.encrypt("Geh-Heim#", pwd));
				System.exit(0);
			}
			String encPwd = System.getenv("DECDOW_PASSWORD");
			String pwd = SimpleCrypto.decrypt("Geh-Heim#", encPwd);
			String keyName = System.getenv("DECDOW_KEYNAME");

			if (args[0].equals("--encrypt-file")) {
				if (args.length != 2) {
					usage();
				}
				String inputFilename = args[1];
				Path inputFile = Paths.get(inputFilename);
				Path outputFile =  Paths.get(inputFilename+".pgp");

				EncrypterWithPW enc = new EncrypterWithPW(pwd);
				
				String name = inputFile.getFileName().toString();
				FileTime time = Files.getLastModifiedTime(inputFile);
				long filesize = Files.size(inputFile);
				String sha256 = Utils.calcFileSHA256(inputFile);
				
				String comment = "sha256="+sha256 + "\n"
						+ "size=" + filesize+"\n"
						+ "time=" + time.toString()+"\n"
						+ "name=" +name+"\n";
				if (keyName != null) {
					comment += "key=" + keyName;
				}
					   
				System.out.println("encrypting "+inputFile+" to "+outputFile);
				EncryptResult result = enc.encrypt(new FileInputStream(inputFile.toFile()), new FileOutputStream(outputFile.toFile()), comment);
				System.out.println(result);

				System.exit(0);
			}
			
			if (args.length != 1) {   // DECDOW_PASSWORD="abc-123" java -jar decrypt-downloader.jar https://filedn.eu/lwAjS7B5boTSPWN01fknj4b/dowdec/test/testdatei.txt.pgp
				usage();
			}
			
			URL url = new URL(args[0]);
			String outfilename = Paths.get(url.getPath()).getFileName().toString();

			URLConnection connection = url.openConnection();
			InputStream is = connection.getInputStream();
			DecrypterWithPW dec = new DecrypterWithPW(pwd);
			
			Path outputFile = Paths.get(outfilename.replaceFirst(".pgp$", ""));
			DecryptResult result = dec.decrypt(is, new FileOutputStream(outputFile.toFile()));
			System.out.println(result);
			if (result.comments.contains("sha256="+result.targetSHA256)) {
				System.err.println("HASHCODEMISMATCH!");
				Files.delete(outputFile);
				System.exit(3);
			}
			else {
				System.out.println("hash code ok.");
			}
			
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(2);
		}
		
	}

	private static void usage() {
		System.err.println("usage: decrypt-downloader <url>");
		System.exit(1);
	}

	
}
