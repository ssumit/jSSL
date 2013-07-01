package prj.jSSL;

import org.slf4j.LoggerFactory;
import prj.jSSL.ssl.BufferAllocator;
import prj.jSSL.ssl.CryptoHelper;
import prj.jSSL.ssl.CustomSSLEngine;
import prj.jSSL.ssl.SSLShakehandsHandler;
import prj.jSSL.store.ISSLStore;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;

public class SSLManager<KEY>
{
    private SSLTransport<KEY> _transport;
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

    public void initSSLEngine(KEY userKey) throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, UnrecoverableKeyException
    {
        CustomSSLEngine sslEngine = new SSLEngineBuilder().createAndInitSSLEngine(_config);
        _store.putSSLEngine(userKey, sslEngine);
        _store.putRemainingData(userKey, new byte[0]);
        _store.setHandShakeCompletedStatus(userKey, false);
    }

    public void beginSSLHandshake(KEY userKey, HandshakeCompletedListener handshakeCompletedListener) throws IOException
    {
        _store.putHandShakeCompletedListener(userKey, handshakeCompletedListener);
        CustomSSLEngine customSSLEngine = getSSLEngine(userKey);
        customSSLEngine.getSSLEngine().beginHandshake();
        shakeHands(userKey);
    }

    public void shakeHands(KEY userKey) throws IOException
    {
        new SSLShakehandsHandler(getSSLEngine(userKey)).shakehands();
    }

    public boolean isHandshakeCompleted(KEY userKey)
    {
        return _store.getHandShakeCompletedStatus(userKey);
    }

    public void send(KEY userKey, byte[] plainBytes) throws IOException
    {
        ByteBuffer encryptedData = allocateByteBuffer(userKey, Operation.SENDING);
        SSLEngineResult result;
        int totalBytesConsumed = 0;
        do
        {
            result = new CryptoHelper().encrypt(getSSLEngine(userKey), Arrays.copyOfRange(plainBytes, totalBytesConsumed, plainBytes.length), encryptedData);
            byte[] sendableData = copyToByteArray(encryptedData, result.bytesProduced());
            _transport.send(userKey, sendableData);
            encryptedData.clear();
            totalBytesConsumed += result.bytesConsumed();
        }
        while (result.getStatus().equals(SSLEngineResult.Status.OK) && totalBytesConsumed < plainBytes.length && result.bytesProduced() > 0);
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
        _store.removeHandShakeCompleteListener(userKey);
        _store.removeRemainingData(userKey);
        _store.removeHandShakeCompleteStatus(userKey);
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
        cleanState(userKey);
    }

    public void setTransport(SSLTransport<KEY> sslTransport)
    {
        _transport = sslTransport;
    }

    public void decrypt(KEY socket, byte[] incomingData) throws IOException
    {
        new CryptoHelper().decrypt(getSSLEngine(socket), incomingData);
    }

    private ByteBuffer allocateByteBuffer(KEY userKey, Operation operation) throws IOException
    {
        return new BufferAllocator().getEmptyByteBuffer(getSSLEngine(userKey), operation);
    }

    private void cleanState(KEY userKey)
    {
        _store.removeSSLEngine(userKey);
        _store.removeHandShakeCompleteListener(userKey);
        _store.removeRemainingData(userKey);
        _store.removeHandShakeCompleteStatus(userKey);
    }

    private byte[] copyToByteArray(ByteBuffer outgoingData, int size)
    {
        outgoingData.flip();
        byte[] bytes = new byte[size];
        outgoingData.get(bytes, 0, size);
        return bytes;
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