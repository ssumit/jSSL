package prj.jSSL.ssl;

import java.io.IOException;

public class SSL
{
    private CustomSSLEngine _sslEngine;
    private SSLShakeHandHandler _sslShakeHandHandler;

    public SSL(CustomSSLEngine sslEngine)
    {
        _sslEngine = sslEngine;
        _sslShakeHandHandler = new SSLShakeHandHandler(sslEngine);
    }

    public void startHandShaking() throws IOException
    {
        _sslShakeHandHandler.shakeHands();
    }

    public void encrypt(String plainData)
    {
        ;
    }

    public void decrypt(String cipherData)
    {
        ;
    }
}
