package prj.jSSL.ssl;

import prj.jSSL.ssl.handshaking.SSLHandshakeStateHolder;

import java.io.IOException;

public class SSLShakeHandHandler
{
    private CustomSSLEngine _sslEngine;

    public SSLShakeHandHandler(CustomSSLEngine sslEngine)
    {
        _sslEngine = sslEngine;
    }

    public void shakeHands() throws IOException
    {
        SSLHandshakeStateHolder sslHandshakeStateHolder = new SSLHandshakeStateHolder(_sslEngine);
        while (sslHandshakeStateHolder.shakeHands());
    }
}
