package prj.jSSL.ssl;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;

public abstract class CustomSSLEngine extends SSLEngine implements IReaderWriter
{
    HandshakeCompletedListener _handshakeCompletedListener;
    protected CustomSSLEngine(HandshakeCompletedListener handshakeCompletedListener)
    {
        super();
        _handshakeCompletedListener = handshakeCompletedListener;
    }

    public String read(ReadEvent readEvent)
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
}
