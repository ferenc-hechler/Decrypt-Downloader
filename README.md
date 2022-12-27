# Download Decryptor

Download a PGP password encrypted file and decrypt it.

# usage

```
DECDOW_PASSWORD="<password>" java -jar download-decrypter <url>
```

# encrypt cli password

```
java -jar download-decrypter --encrypt-password <password>
```

# test


```
DECDOW_PASSWORD="F84C7CC2506DE417A6489FE2A0BD58CF" java -jar decrypt-downloader-jar-with-dependencies.jar https://filedn.eu/lwAjS7B5boTSPWN01fknj4b/dowdec/test/testdatei.txt.pgp
```
