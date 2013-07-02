package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CryptoHelper;
import prj.jSSL.ssl.CustomSSLEngine;

import javax.net.ssl.SSLEngineResult;
import java.io.IOException;

public class NeedWrapState extends IHandShakeState
{
    public NeedWrapState(CustomSSLEngine sslEngine)
    {
        super(sslEngine);
    }

    @Override
    public boolean shakeHands() throws IOException
    {
        new CryptoHelper().encrypt(customSSLEngine, new byte[0]);
        if(customSSLEngine.getSSLEngine().getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED))
        {
            finishHandshake(); //we will go to finish state
            return true;
        }
        else
        {
            return false;
        }
    }
}
