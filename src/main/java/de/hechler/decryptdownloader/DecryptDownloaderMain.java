package de.hechler.decryptdownloader;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Path;
import java.nio.file.Paths;

import de.hechler.pgpencrypter.decrypt.DecrypterWithPW;
import de.hechler.pgpencrypter.decrypt.DecrypterWithPW.DecryptResult;
import de.hechler.pgpencrypter.utils.SimpleCrypto;

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
			if (args.length != 1) {   // https://filedn.eu/lwAjS7B5boTSPWN01fknj4b/decdow/test.txt.pgp
				usage();
			}
			
			String encPwd = System.getenv("DECDOW_PASSWORD");
			String pwd = SimpleCrypto.decrypt("Geh-Heim#", encPwd);
			
			
			URL url = new URL(args[0]);
			String outfilename = Paths.get(url.getPath()).getFileName().toString();

			URLConnection connection = url.openConnection();
			InputStream is = connection.getInputStream();
			DecrypterWithPW dec = new DecrypterWithPW(pwd);
			
			Path outputFile = Paths.get(outfilename.replaceFirst(".pgp$", ""));
			System.out.println("downloading "+url+" to "+outputFile.toAbsolutePath());
			DecryptResult result = dec.decrypt(is, new FileOutputStream(outputFile.toFile()));
			System.out.println(result);

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
