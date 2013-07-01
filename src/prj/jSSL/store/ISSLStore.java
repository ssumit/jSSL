package prj.jSSL.store;

import prj.jSSL.ssl.CustomSSLEngine;

import javax.net.ssl.HandshakeCompletedListener;

public interface ISSLStore<KEY>
{
    public void putHandShakeCompletedListener(KEY userKey, HandshakeCompletedListener handshakeCompletedListener);

    public CustomSSLEngine getSSLEngine(KEY key);

    public void putRemainingData(KEY userKey, byte[] bytes);

    public boolean getHandShakeCompletedStatus(KEY userKey);

    public byte[] getRemainingData(KEY userKey);

    public void setHandShakeCompletedStatus(KEY userKey, boolean b);

    public HandshakeCompletedListener getHandShakeCompletedListener(KEY userKey);

    public void removeHandShakeCompleteListener(KEY userKey);

    public void putSSLEngine(KEY userKey, CustomSSLEngine sslEngine);

    public void removeSSLEngine(KEY userKey);

    public void removeRemainingData(KEY userKey);

    public void removeHandShakeCompleteStatus(KEY userKey);
}
