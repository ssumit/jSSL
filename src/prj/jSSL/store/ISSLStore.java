package prj.jSSL.store;

import prj.jSSL.ssl.CustomSSLEngine;

public interface ISSLStore<KEY>
{
    public CustomSSLEngine getSSLEngine(KEY key);

    public void putSSLEngine(KEY userKey, CustomSSLEngine sslEngine);

    public void removeSSLEngine(KEY userKey);
}
