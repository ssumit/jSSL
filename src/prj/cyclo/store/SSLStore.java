package prj.cyclo.store;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;
import java.util.HashMap;
import java.util.Map;

public class SSLStore<KEY> implements ISSLStore<KEY>
{
    private final Map<KEY, SSLEngine> _sslEngines;
    private final Map<KEY, HandshakeCompletedListener> _handshakeCompletedListeners;
    private final Map<KEY, byte[]> _remainingData;
    private final Map<KEY, Boolean> _handshakeCompletedStatus;

    public SSLStore()
    {
        _sslEngines = new HashMap<>();
        _remainingData = new HashMap<>();
        _handshakeCompletedStatus = new HashMap<>();
        _handshakeCompletedListeners = new HashMap<>();
    }

    @Override
    public void putHandShakeCompletedListener(KEY userKey, HandshakeCompletedListener handshakeCompletedListener)
    {
        _handshakeCompletedListeners.put(userKey, handshakeCompletedListener);
    }

    @Override
    public SSLEngine getSSLEngine(KEY key)
    {
        return _sslEngines.get(key);
    }

    @Override
    public void putRemainingData(KEY userKey, byte[] bytes)
    {
        _remainingData.put(userKey, new byte[0]);
    }

    @Override
    public boolean getHandShakeCompletedStatus(KEY userKey)
    {
        return _handshakeCompletedStatus.get(userKey);
    }

    @Override
    public byte[] getRemainingData(KEY userKey)
    {
        return _remainingData.get(userKey);
    }

    @Override
    public void setHandShakeCompletedStatus(KEY userKey, boolean b)
    {
        _handshakeCompletedStatus.put(userKey, b);
    }

    @Override
    public HandshakeCompletedListener getHandShakeCompletedListener(KEY userKey)
    {
        return _handshakeCompletedListeners.get(userKey);
    }

    @Override
    public void removeHandShakeCompleteListener(KEY userKey)
    {
        _handshakeCompletedListeners.remove(userKey);
    }

    @Override
    public void putSSLEngine(KEY userKey, SSLEngine sslEngine)
    {
        _sslEngines.put(userKey, sslEngine);
    }

    @Override
    public void removeSSLEngine(KEY userKey)
    {
        _sslEngines.remove(userKey);
    }

    @Override
    public void removeRemainingData(KEY userKey)
    {
        _remainingData.remove(userKey);
    }

    @Override
    public void removeHandShakeCompleteStatus(KEY userKey)
    {
        _handshakeCompletedStatus.remove(userKey);
    }
}
