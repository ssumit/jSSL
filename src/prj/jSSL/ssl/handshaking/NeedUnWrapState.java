package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CryptoHelper;
import prj.jSSL.ssl.CustomSSLEngine;

import java.io.IOException;

public class NeedUnWrapState extends IHandShakeState
{
    public NeedUnWrapState(CustomSSLEngine _sslEngine)
    {
        super(_sslEngine);
    }

    @Override
    public void shakeHands() throws IOException
    {
        System.out.println("unwrap state");
        CryptoHelper cryptoHelper = new CryptoHelper();
        cryptoHelper.decrypt(customSSLEngine, new byte[0]);
    }
}
