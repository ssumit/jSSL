package prj.jSSL.ssl;

import java.io.IOException;

public class SSL
{
    private CustomSSLEngine _sslEngine;
    private SSLShakehandsHandler _sslShakehandsHandler;

    public SSL(CustomSSLEngine sslEngine)
    {
        _sslEngine = sslEngine;
        _sslShakehandsHandler = new SSLShakehandsHandler(sslEngine);
    }

    public void startHandShaking() throws IOException
    {
        _sslShakehandsHandler.shakehands();
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
