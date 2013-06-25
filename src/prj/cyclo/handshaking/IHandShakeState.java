package prj.cyclo.handshaking;

import prj.cyclo.store.ISSLStore;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;

public abstract class IHandShakeState<KEY>
{
    protected ISSLStore<KEY> _store;

    public IHandShakeState(ISSLStore store)
    {
        _store = store;
    }

    public abstract boolean shakeHands() throws IOException;

    protected void finishHandshake(KEY userKey)
    {
        _store.setHandShakeCompletedStatus(userKey, true);
        HandshakeCompletedListener handshakeCompletedListener =_store.getHandShakeCompletedListener(userKey);
        if(handshakeCompletedListener != null)
        {
            handshakeCompletedListener.handshakeCompleted(null);
        }
        _store.removeHandShakeCompleteListener(userKey);
    }

    protected SSLEngine getSSLEngine(KEY key) throws IOException
    {
        SSLEngine sslEngine = _store.getSSLEngine(key);
        if (sslEngine != null)
        {
            return sslEngine;
        }
        else
        {
            throw new IOException("user key (ssl engine) not present in map");
        }
    }

    protected boolean isHandshakeStatusFinished(SSLEngineResult result)
    {
        return result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED);
    }
}
