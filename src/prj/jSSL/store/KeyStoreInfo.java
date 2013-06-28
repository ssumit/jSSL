package prj.jSSL.store;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class KeyStoreInfo
{
    private String name;
    private String type;
    private String password;
    private String protocol;

    public KeyStoreInfo(String name, String type, String password, String protocol)
    {
        this.name = name;
        this.type = type;
        this.password = password;
        this.protocol = protocol;
    }

    public SSLContext getSSLContext() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException
    {
        char[] passphrase = password.toCharArray();
        java.security.KeyStore ks = java.security.KeyStore.getInstance(type);
        FileInputStream stream = new FileInputStream(name);
        ks.load(stream, passphrase);
        stream.close();
        SSLContext sslContext = SSLContext.getInstance(protocol);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, passphrase);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }
}
