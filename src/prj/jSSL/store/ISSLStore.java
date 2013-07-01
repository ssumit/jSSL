package prj.jSSL.store;

import prj.jSSL.ssl.CustomSSLEngine;

public interface ISSLStore<KEY>
{
    public CustomSSLEngine getSSLEngine(KEY key);

    public void putRemainingData(KEY userKey, byte[] bytes);

    public boolean getHandShakeCompletedStatus(KEY userKey);

    public byte[] getRemainingData(KEY userKey);

    public void setHandShakeCompletedStatus(KEY userKey, boolean b);

    public void putSSLEngine(KEY userKey, CustomSSLEngine sslEngine);

    public void removeSSLEngine(KEY userKey);

    public void removeRemainingData(KEY userKey);

    public void removeHandShakeCompleteStatus(KEY userKey);
}
