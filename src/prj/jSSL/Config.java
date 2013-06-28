package prj.jSSL;

import prj.jSSL.store.KeyStoreInfo;

public class Config
{
    private String[] cipherSuites;
    private boolean twoWayAuth;
    private boolean clientMode;
    private KeyStoreInfo keyStoreInfo;

    public Config()
    {
        clientMode = false;
        twoWayAuth = false;
    }

    public boolean isClientMode()
    {
        return clientMode;
    }

    public void setClientMode(boolean clientMode)
    {
        this.clientMode = clientMode;
    }

    public void setCipherSuites(String[] cipherSuites)
    {
        this.cipherSuites = cipherSuites;
    }

    public void setTwoWayAuth(boolean twoWayAuth)
    {
        this.twoWayAuth = twoWayAuth;
    }

    public void setKeyStoreInfo(KeyStoreInfo keyStoreInfo)
    {
        this.keyStoreInfo = keyStoreInfo;
    }

    public String[] getCipherSuites()
    {
        return cipherSuites;
    }

    public boolean isTwoWayAuth()
    {
        return twoWayAuth;
    }

    public KeyStoreInfo getKeyStoreInfo()
    {
        return keyStoreInfo;
    }
}
