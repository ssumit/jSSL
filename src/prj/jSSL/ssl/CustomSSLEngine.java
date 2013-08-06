package prj.jSSL.ssl;

import javax.net.ssl.SSLEngine;

public class CustomSSLEngine implements IReaderWriter
{
    private SSLEngine mSSLEngine;
    private IReaderWriter mReaderWriter;

    public CustomSSLEngine(SSLEngine sslEngine, IReaderWriter readerWriter)
    {
        mSSLEngine = sslEngine;
        mReaderWriter = readerWriter;
    }

    @Override
    public byte[] read(ReadEvent readEvent)
    {
        System.out.println("read : customSSLE data,  read event : " + readEvent);
        return mReaderWriter.read(readEvent);
    }

    @Override
    public boolean hasData(ReadEvent readEvent)
    {
        return mReaderWriter.hasData(readEvent);
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
