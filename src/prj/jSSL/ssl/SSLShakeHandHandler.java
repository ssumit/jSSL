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
            System.out.println("state : " + status.name());
            if (status.equals(SSLEngineResult.HandshakeStatus.NEED_TASK))
            {
                sslHandshakeStateHolder.shakeHands();
            }
            else
            {
                sslHandshakeStateHolder.shakeHands();
                break;
            }
        }
    }
}
