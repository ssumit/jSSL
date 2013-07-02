package prj.jSSL;

import org.slf4j.LoggerFactory;
import prj.jSSL.ssl.CryptoHelper;
import prj.jSSL.ssl.CustomSSLEngine;
import prj.jSSL.ssl.IReaderWriter;
import prj.jSSL.ssl.SSLShakehandsHandler;
import prj.jSSL.store.ISSLStore;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class SSLManager<KEY>
{
    private ISSLStore<KEY> _store;
    private Config _config;
    private org.slf4j.Logger _logger = LoggerFactory.getLogger(SSLManager.this.getClass().getSimpleName());

    public SSLManager(ISSLStore<KEY> store, Config config)
    {
        _store = store;
        _config = config;
    }

    public void setConfig(KEY userKey, Config config) throws IOException
    {
        _config = config;
        new SSLEngineBuilder().initSSLEngine(config, getSSLEngine(userKey).getSSLEngine());
    }

    public void initSSLEngine(KEY userKey, HandshakeCompletedListener handshakeCompletedListener, IReaderWriter readerWriter) throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, UnrecoverableKeyException
    {
        CustomSSLEngine sslEngine = new SSLEngineBuilder().createAndInitSSLEngine(_config, handshakeCompletedListener, readerWriter);
        _store.putSSLEngine(userKey, sslEngine);
    }

    public void beginSSLHandshake(KEY userKey) throws IOException
    {
        CustomSSLEngine customSSLEngine = getSSLEngine(userKey);
        customSSLEngine.getSSLEngine().beginHandshake();
        shakeHands(userKey);
    }

    public void shakeHands(KEY userKey) throws IOException
    {
        new SSLShakehandsHandler(getSSLEngine(userKey)).shakehands();
    }

    public void encrypt(KEY userKey, byte[] plainBytes) throws IOException
    {
        new CryptoHelper().encrypt(getSSLEngine(userKey), plainBytes);
    }

    public void invalidateSession(KEY userKey)
    {
        try
        {
            SSLEngine engine = getSSLEngine(userKey).getSSLEngine();
            engine.getHandshakeSession().invalidate();
        }
        catch (IOException e)
        {
        }
    }

    public void closeEngine(KEY userKey)
    {
        try
        {
            SSLEngine engine = getSSLEngine(userKey).getSSLEngine();
            engine.closeOutbound();
            engine.closeInbound();
        }
        catch (IOException ignored)
        {
        }
        _store.removeSSLEngine(userKey);
    }

    public void decrypt(KEY socket, byte[] incomingData) throws IOException
    {
        new CryptoHelper().decrypt(getSSLEngine(socket), incomingData);
    }

    private CustomSSLEngine getSSLEngine(KEY key) throws IOException
    {
        CustomSSLEngine sslEngine = _store.getSSLEngine(key);
        if (sslEngine != null)
        {
            return sslEngine;
        }
        else
        {
            _logger.warn("user key {} not present in map", key);
            throw new IOException("user key not present in map");
        }
    }

    public enum Operation
    {
        SENDING, RECEIVING
    }
}