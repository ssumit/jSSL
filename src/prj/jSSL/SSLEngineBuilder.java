package prj.jSSL;

import prj.jSSL.ssl.CustomSSLEngine;
import prj.jSSL.ssl.IReaderWriter;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SSLEngineBuilder
{
    public CustomSSLEngine createAndInitSSLEngine(Config config, HandshakeCompletedListener handshakeCompletedListener, IReaderWriter readerWriter) throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, UnrecoverableKeyException
    {
        SSLContext sslcontext = config.getKeyStoreInfo().getSSLContext();
        SSLEngine sslEngine = sslcontext.createSSLEngine();
        initSSLEngine(config, sslEngine);
        CustomSSLEngine customSSLEngine = new CustomSSLEngine(sslEngine, handshakeCompletedListener, readerWriter);
        return customSSLEngine;
    }

    public void initSSLEngine(Config config, SSLEngine sslEngine)
    {
        sslEngine.setUseClientMode(config.isClientMode());
        sslEngine.setNeedClientAuth(config.isTwoWayAuth());
        setCipherSuite(config, sslEngine);
    }

    private void setCipherSuite(Config config, SSLEngine sslEngine)
    {
        String[] cipherSuites = config.getCipherSuites();
        if(cipherSuites != null)
        {
            List<String> list = Arrays.asList(sslEngine.getEnabledCipherSuites());
            List<String> newList = new ArrayList<>();
            for (String cipherSuite : cipherSuites)
            {
                if(list.contains(cipherSuite))
                {
                    newList.add(cipherSuite);
                }
            }
            if(newList.size()>0)
            {
                sslEngine.setEnabledCipherSuites((String[]) newList.toArray());
            }
        }
    }
}