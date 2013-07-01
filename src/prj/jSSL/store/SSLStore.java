package prj.jSSL.store;

import prj.jSSL.ssl.CustomSSLEngine;

import java.util.HashMap;
import java.util.Map;

public class SSLStore<KEY> implements ISSLStore<KEY>
{
    private final Map<KEY, CustomSSLEngine> _sslEngines;
    private final Map<KEY, byte[]> _remainingData;
    private final Map<KEY, Boolean> _handshakeCompletedStatus;

    public SSLStore()
    {
        _sslEngines = new HashMap<>();
        _remainingData = new HashMap<>();
        _handshakeCompletedStatus = new HashMap<>();
    }

    @Override
    public CustomSSLEngine getSSLEngine(KEY key)
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
    public void putSSLEngine(KEY userKey, CustomSSLEngine sslEngine)
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
