package prj.jSSL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import prj.jSSL.ssl.IReaderWriter;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import java.io.IOException;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public abstract class SecureAgent extends Agent
{
    private static final long HANDSHAKE_TIMEOUT_IN_SECONDS = 60;
    private prj.jSSL.SSLManager<Socket> _sslManager;
    private IReaderWriter _sslTransport;
    private final Logger _logger = LoggerFactory.getLogger(this.getClass().getSimpleName());
    private final Map<Socket, ScheduledFuture> _handshakeTimeoutTasks = new HashMap<>();

    protected SecureAgent(TCPReactor reactor, ScheduledExecutorService threadPool, SSLManager<Socket> sslManager)
    {
        super(reactor, threadPool);
        setupSSL(sslManager);
    }


    public SecureAgent(TCPReactor reactor, SSLManager<Socket> sslManager)
    {
        super(reactor);
        setupSSL(sslManager);
    }

    private void setupSSL(SSLManager<Socket> sslManager)
    {
        _sslManager = sslManager;
        _sslTransport = new IReaderWriter() {
            @Override
            public byte[] read(ReadEvent readEvent)
            {
                System.out.println("read event : " + readEvent);
                return new byte[0];
            }

            @Override
            public void write(WriteEvent writeEvent, byte[] dataToBeWritten)
            {
                System.out.println("write event : " + writeEvent + " data : " + dataToBeWritten);
            }
        };
    }

    public abstract void secureConnectionMade(Socket socket);

    public abstract void secureReceive(Socket socket, byte[] incomingData);

    @Override
    public final void connectionMade(final Socket socket)
    {
        try
        {
            _sslManager.initSSLEngine(socket, new HandshakeCompletedListener()
            {
                public void handshakeCompleted(HandshakeCompletedEvent alwaysNull)
                {
                    cancelHandshakeTimeoutTask(socket);
                    secureConnectionMade(socket);
                }
            }, _sslTransport);
            final ScheduledFuture handShakeTimeoutTask = scheduleHandshakeTimeout(socket);
            _handshakeTimeoutTasks.put(socket, handShakeTimeoutTask);

            _sslManager.beginSSLHandshake(socket);
        }
        catch (Exception e)
        {
            if (e instanceof IOException)
            {
                _logger.debug("IOException during SSLHandshake in SecureAgent.connectionMade, closing socket: {}", socket);
            }
            else
            {
                _logger.error("Exception during SSLHandshake in SecureAgent.connectionMade, closing socket: ", e);
            }
            close(socket);
        }
    }

    private ScheduledFuture scheduleHandshakeTimeout(final Socket socket)
    {
        return _agency.schedule(new Runnable()
        {
            @Override
            public void run()
            {
                _logger.info("Handshake timed out. Closing socket {}", socket);
                _handshakeTimeoutTasks.remove(socket);
                close(socket);
            }
        }, HANDSHAKE_TIMEOUT_IN_SECONDS, TimeUnit.SECONDS);
    }

    public final void receive(Socket socket, byte[] incomingData)
    {
        try
        {
            _sslManager.decrypt(socket, incomingData);
/*            if (_sslManager.isHandshakeCompleted(socket))
            {
                //secureReceive(socket, decryptedBytes); will do via listeners
            }
            else
            {
                _sslManager.shakeHands(socket); //will do via listeners
            }*/
        }
        catch (Exception e)
        {
            if (e instanceof IOException)
            {
                _logger.debug("IOException in SecureAgent.receive, closing socket: {}", socket);
            }
            else
            {
                _logger.error("Exception in SecureAgent.receive, closing socket: ", e);
            }
            close(socket);
        }

    }

    public final void secureSend(Socket socket, byte[] plainData) throws IOException
    {
        try
        {
            _sslManager.encrypt(socket, plainData);
        }
        catch (Exception e)
        {
            if (e instanceof IOException)
            {
                _logger.info("IOException in secure send: {}", socket);
            }
            else
            {
                _logger.error("exception in secure send: ", e);
            }
            throw new IOException(e);
        }
    }

    @Override
    public final void close(Socket socket)
    {
        cancelHandshakeTimeoutTask(socket);
        _sslManager.closeEngine(socket);
        super.close(socket);
        secureClose(socket);
    }

    @Override
    public void onClose(Socket socket)
    {
        close(socket);
    }

    public void secureClose(Socket socket)
    {
        //Extending class should override this
    }

    @Override
    public final void send(Socket socket, byte[] data) throws IOException
    {
        secureSend(socket, data);
    }

    private void cancelHandshakeTimeoutTask(Socket socket)
    {
        ScheduledFuture handshakeTimeoutTask = _handshakeTimeoutTasks.remove(socket);
        if (handshakeTimeoutTask != null)
        {
            handshakeTimeoutTask.cancel(false);
        }
    }

}
