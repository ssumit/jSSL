package prj.jSSL.ssl.handshaking;

import prj.jSSL.ssl.CryptoHelper;
import prj.jSSL.ssl.CustomSSLEngine;

import java.io.IOException;

public class NeedWrapState extends IHandShakeState
{
    public NeedWrapState(CustomSSLEngine sslEngine)
    {
        super(sslEngine);
        System.out.println("need wrap state wrap shake constructor");
    }

    @Override
    public boolean shakeHands() throws IOException
    {
        System.out.println("need wrap state wrap shake hands start");
        new CryptoHelper().encrypt(customSSLEngine, new byte[0]);
        return true;
    }
}
