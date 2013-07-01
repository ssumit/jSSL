package prj.jSSL.ssl;

import prj.jSSL.SSLManager;

import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;

public class BufferAllocator
{
    public ByteBuffer getEmptyByteBuffer(CustomSSLEngine customSSLEngine, SSLManager.Operation operation) throws IOException
    {
        SSLSession session = customSSLEngine.getSSLEngine().getSession();
        int bufferSize = getBufferSize(operation, session);
        return ByteBuffer.allocate(bufferSize);
    }

    private int getBufferSize(SSLManager.Operation operation, SSLSession session) {
        int bufferSize;
        if (operation == SSLManager.Operation.SENDING)
        {
            bufferSize = session.getPacketBufferSize();
        }
        else
        {
            bufferSize = session.getApplicationBufferSize();
        }
        return bufferSize;
    }

}
