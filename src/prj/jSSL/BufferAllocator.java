package prj.jSSL;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;

public class BufferAllocator<KEY>
{
    public ByteBuffer allocateByteBuffer(SSLEngine sslEngine, SSLManager.Operation operation) throws IOException
    {
        SSLSession session = sslEngine.getSession();
        int bufferSize;
        if (operation == SSLManager.Operation.SENDING)
        {
            bufferSize = session.getPacketBufferSize();
        }
        else
        {
            bufferSize = session.getApplicationBufferSize();
        }
        return ByteBuffer.allocate(bufferSize);
    }

}
