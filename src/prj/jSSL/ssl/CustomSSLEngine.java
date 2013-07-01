package prj.jSSL.ssl;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;

public class CustomSSLEngine implements IReaderWriter
{
    HandshakeCompletedListener _handshakeCompletedListener;
    private SSLEngine mSSLEngine;

    public CustomSSLEngine(SSLEngine sslEngine, HandshakeCompletedListener handshakeCompletedListener)
    {
        mSSLEngine = sslEngine;
        _handshakeCompletedListener = handshakeCompletedListener;
    }

    public byte[] read(ReadEvent readEvent)
    {
        return null;
    }

    public void write(WriteEvent writeEvent, String dataToBeWritten)
    {
        switch (writeEvent)
        {
            case HANDSHAKE_COMPLETE_STATUS:
                if(dataToBeWritten.equals(String.valueOf(true)))
                {
                    _handshakeCompletedListener.handshakeCompleted(null);
                }
        }
    }

    public SSLEngine getSSLEngine()
    {
        return mSSLEngine;
    }
}
