package prj.cyclo;

import org.slf4j.LoggerFactory;
import prj.cyclo.handshaking.SSLHandshakeStateHolder;
import prj.cyclo.store.ISSLStore;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;

public class SSLShakehandsHandler<KEY>
{
    private KEY _userKey;
    private ISSLStore<KEY> _store;
    private SSLTransport<KEY> _transport;

    private org.slf4j.Logger _logger = LoggerFactory.getLogger(SSLShakehandsHandler.this.getClass().getSimpleName());

    public SSLShakehandsHandler(KEY userKey, ISSLStore<KEY> store)
    {
        _userKey = userKey;
        _store = store;
        _transport = null;
    }

    public SSLShakehandsHandler(KEY userKey, ISSLStore<KEY> store, SSLTransport<KEY> transport)
    {
        _userKey = userKey;
        _store = store;
        _transport = transport;
    }

    public void shakehands(KEY userKey) throws IOException
    {
        SSLEngine sslEngine = getSSLEngine(userKey);
        while (true)
        {
            SSLEngineResult.HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();
            SSLHandshakeStateHolder sslHandshakeStateHolder = new SSLHandshakeStateHolder(handshakeStatus, userKey, _store, _transport);
            if(sslHandshakeStateHolder.shakeHands())
            {
                return;
            }
        }
    }

    public void finishShakeHand(KEY userKey) throws IOException
    {
        SSLHandshakeStateHolder sslHandshakeStateHolder = new SSLHandshakeStateHolder(SSLEngineResult.HandshakeStatus.FINISHED, userKey, _store, _transport);
        sslHandshakeStateHolder.shakeHands();
    }

    private SSLEngine getSSLEngine(KEY key) throws IOException
    {
        SSLEngine sslEngine = _store.getSSLEngine(key);
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
}
