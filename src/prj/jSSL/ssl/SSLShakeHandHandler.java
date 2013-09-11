package prj.jSSL.ssl;

import prj.jSSL.ssl.handshaking.SSLHandshakeStateHolder;

import javax.net.ssl.SSLEngineResult;
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
        while (true)
        {
            SSLEngineResult.HandshakeStatus status = _sslEngine.getHandshakeStatus();
            if (status.equals(SSLEngineResult.HandshakeStatus.NEED_TASK))
            {
                sslHandshakeStateHolder.shakeHands();
                break;
            }
            else
            {
                sslHandshakeStateHolder.shakeHands();
            }
        }
    }
}
