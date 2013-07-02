package prj.jSSL.store;

import prj.jSSL.ssl.CustomSSLEngine;

import java.util.HashMap;
import java.util.Map;

public class SSLStore<KEY> implements ISSLStore<KEY>
{
    private final Map<KEY, CustomSSLEngine> _sslEngines;

    public SSLStore()
    {
        _sslEngines = new HashMap<>();
    }

    @Override
    public CustomSSLEngine getSSLEngine(KEY key)
    {
        return _sslEngines.get(key);
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

}
