package prj.jSSL.ssl;

import prj.jSSL.ssl.handshaking.SSLHandshakeStateHolder;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;

public class SSLShakehandsHandler
{
    private CustomSSLEngine _sslEngine;

    public SSLShakehandsHandler(CustomSSLEngine sslEngine)
    {
        _sslEngine = sslEngine;
    }

    public void shakehands() throws IOException
    {
        SSLHandshakeStateHolder sslHandshakeStateHolder = new SSLHandshakeStateHolder(_sslEngine);
        while (sslHandshakeStateHolder.shakeHands());
    }

    public void finishShakeHand() throws IOException
    {
        SSLHandshakeStateHolder sslHandshakeStateHolder = new SSLHandshakeStateHolder(SSLEngineResult.HandshakeStatus.FINISHED, _sslEngine);
        sslHandshakeStateHolder.shakeHands();
    }
}
