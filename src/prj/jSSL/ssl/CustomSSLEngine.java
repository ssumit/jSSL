package prj.jSSL.ssl;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLEngine;

public class CustomSSLEngine implements IReaderWriter
{
    private HandshakeCompletedListener mHandshakeCompletedListener;
    private SSLEngine mSSLEngine;
    private IReaderWriter mReaderWriter;

    public CustomSSLEngine(SSLEngine sslEngine, HandshakeCompletedListener handshakeCompletedListener, IReaderWriter readerWriter)
    {
        mSSLEngine = sslEngine;
        mHandshakeCompletedListener = handshakeCompletedListener;
        mReaderWriter = readerWriter;
    }

    @Override
    public byte[] read(ReadEvent readEvent)
    {
        System.out.println("read : customSSLE data,  read event : " + readEvent);
        return mReaderWriter.read(readEvent);
    }

    @Override
    public void write(WriteEvent writeEvent, byte[] dataToBeWritten)
    {
        System.out.println("write : customSSLE data : " + dataToBeWritten + " write event : " + writeEvent);
        mReaderWriter.write(writeEvent, dataToBeWritten);
    }

    public SSLEngine getSSLEngine()
    {
        return mSSLEngine;
    }
}
