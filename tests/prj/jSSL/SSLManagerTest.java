package prj.jSSL;

import org.junit.Before;
import org.junit.Test;
import prj.jSSL.ssl.IReaderWriter;
import prj.jSSL.store.KeyStoreInfo;
import prj.jSSL.store.SSLStore;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import java.io.IOException;

import static junit.framework.Assert.assertTrue;

public class SSLManagerTest
{
    private SSLManager<Integer> sslServer;
    private SSLManager<Integer> sslClient;

    @Before
    public void init()
    {
        String keyValueStoreName = "cyclekeystore";
        String keyValueStoreType = "JKS";
        String keyValueStorePassword = "qwerty";
        String keyValueStoreProtocol= "TLS";
        KeyStoreInfo keyStoreInfo = new KeyStoreInfo(keyValueStoreName, keyValueStoreType, keyValueStorePassword, keyValueStoreProtocol);
        Config serverConfig = new Config();
        serverConfig.setClientMode(false);
        serverConfig.setKeyStoreInfo(keyStoreInfo);
        Config clientConfig = new Config();
        clientConfig.setClientMode(true);
        clientConfig.setKeyStoreInfo(keyStoreInfo);
        sslServer = new SSLManager<>(new SSLStore<Integer>(), serverConfig);
        sslClient = new SSLManager<>(new SSLStore<Integer>(), clientConfig);
    }

    @Test
    public void testHandshake() throws Exception
    {

        final Integer CLIENT = 9;
        final Integer SERVER = 10;

        IReaderWriter _sslServerTransport = new IReaderWriter() {
            byte[] remaingingData = new byte[0];
            @Override
            public byte[] read(ReadEvent readEvent)
            {
                System.out.println("read event : " + readEvent);
                switch (readEvent)
                {
                    case REMAINING_DATA:
                        return remaingingData;
                    default:
                        return new byte[0];
                }
            }

            @Override
            public void write(WriteEvent writeEvent, byte[] dataToBeWritten)
            {
                System.out.println("write event : " + writeEvent + " data : " + dataToBeWritten);
                System.out.println("S > C: " + dataToBeWritten.length);
                System.out.println("SSLClient| Received data");
                try {
                    switch (writeEvent)
                    {
                        case REMAINING_DATA:
                            byte[] temp = new byte[remaingingData.length + dataToBeWritten.length];
                            System.arraycopy(remaingingData, 0, temp, 0, remaingingData.length);
                            System.arraycopy(dataToBeWritten, 0, temp, remaingingData.length, dataToBeWritten.length);
                            remaingingData = temp;
                            break;
                        case HANDSHAKE_COMPLETE_STATUS:
                            break;
                        case WRAP_STATE:
                            sslClient.decrypt(SERVER, dataToBeWritten);
                            break;
                        case UNWRAP_STATE:
                            break;
                    }
                    sslClient.shakeHands(SERVER);
                } catch (IOException e) {
                    System.out.println("S > C: : IOEXCEPTION" );
                }
            }
        };

        IReaderWriter _sslClientTransport = new IReaderWriter() {
            byte[] remaingingData = new byte[0];
            @Override
            public byte[] read(ReadEvent readEvent)
            {
                System.out.println("read event : " + readEvent);
                switch (readEvent)
                {
                    case REMAINING_DATA:
                        return remaingingData;
                    default:
                        return new byte[0];
                }
            }

            @Override
            public void write(WriteEvent writeEvent, byte[] dataToBeWritten)
            {
                System.out.println("write event : " + writeEvent + " data : " + dataToBeWritten);
                System.out.println("C > S: " + dataToBeWritten.length);
                System.out.println("SSLServer| Received data");
                try{
                    switch (writeEvent)
                    {
                        case REMAINING_DATA:
                            byte[] temp = new byte[remaingingData.length + dataToBeWritten.length];
                            System.arraycopy(remaingingData, 0, temp, 0, remaingingData.length);
                            System.arraycopy(dataToBeWritten, 0, temp, remaingingData.length, dataToBeWritten.length);
                            remaingingData = temp;
                            break;
                        case HANDSHAKE_COMPLETE_STATUS:
                            break;
                        case WRAP_STATE:
                            sslServer.decrypt(CLIENT, dataToBeWritten);
                            break;
                        case UNWRAP_STATE:
                            break;
                    }
                    sslServer.shakeHands(CLIENT);
                }
                catch (IOException e)
                {
                    System.out.println("C > S: : IOEXCEPTION" );
                }
            }
        };

        sslServer.initSSLEngine(CLIENT, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                System.out.println("Server Done");
                assertTrue(true);
            }
        }, _sslServerTransport);

        sslClient.initSSLEngine(SERVER, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                System.out.println("Client Done");
                assertTrue(true);
            }
        }, _sslClientTransport);

        System.out.println("SSLCLIENT| handshake begins");
        sslClient.beginSSLHandshake(SERVER);

        System.out.println("SSLServer| handshake begins");
        sslServer.beginSSLHandshake(CLIENT);
    }

    @Test
    public void testDataSent() throws Exception
    {
        final Integer CLIENT = 9;
        final Integer SERVER = 10;

        final String sampleString = "Test data datadata data data data data data data data data data data data data data data data data  data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data data ";
        final byte[] sampleData = sampleString.getBytes();


/*
        SSLTransport<Integer> serverTransport = new SSLTransport<Integer>()
        {
            @Override
            public void send(Integer key, byte[] data) throws IOException
            {
                sslClient.decrypt(SERVER, data);
                sslClient.shakeHands(SERVER);
            }
        };
        SSLTransport<Integer> clientTransport = new SSLTransport<Integer>()
        {
            @Override
            public void send(Integer key, byte[] data) throws IOException
            {
                sslServer.decrypt(CLIENT, data);
                if (sslClient.isHandshakeCompleted(SERVER))
                {
                    byte[] decryptedBytes = Arrays.copyOfRange(decryptedData.array(), 0, decryptedData.position());
                    String decryptedString = new String(decryptedBytes);
                    assertEquals(sampleString.length(), decryptedString.length());
                    assertTrue(sampleString.equals(decryptedString));
                    return;
                }
                if (!sslServer.isHandshakeCompleted(CLIENT))
                {
                    sslServer.shakeHands(CLIENT);
                    return;
                }
            }
        };
*/

/*
        sslServer.initSSLEngine(CLIENT, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                assertTrue(true);
            }
        });
        sslClient.initSSLEngine(SERVER, new HandshakeCompletedListener()
        {
            @Override
            public void handshakeCompleted(HandshakeCompletedEvent handshakeCompletedEvent)
            {
                try
                {
                    sslClient.encrypt(SERVER, sampleData);
                }
                catch (IOException e)
                {
                    fail(e.toString());
                }
            }
        });
*/

        sslServer.beginSSLHandshake(CLIENT);

        sslClient.beginSSLHandshake(SERVER);
    }
}
