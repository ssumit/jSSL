import prj.jSSL.Config;
import prj.jSSL.SSLManager;
import prj.jSSL.SecureAgent;
import prj.jSSL.TCPReactor;
import prj.jSSL.store.KeyStoreInfo;
import prj.jSSL.store.SSLStore;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class dummyServer
{
    public static void main(String[] args)
    {
        String keyValueStoreName = "cyclekeystore";
        String keyValueStoreType = "JKS";
        String keyValueStorePassword = "qwerty";
        String keyValueStoreProtocol= "TLS";
        try {
            KeyStoreInfo keyStoreInfo = new KeyStoreInfo(keyValueStoreName, keyValueStoreType, keyValueStorePassword, keyValueStoreProtocol);
            Config config = new Config();
            config.setClientMode(false);
            config.setKeyStoreInfo(keyStoreInfo);
            SSLManager<Socket> sslServer = new SSLManager<>(new SSLStore<Socket>(), config);
            TCPReactor reactor = TCPReactor.initiate();
            SecureAgent serverAgent = new SecureAgent(reactor, sslServer) {
                @Override
                public void secureConnectionMade(Socket socket) {
                    System.out.println("secure connection made");
                }

                @Override
                public void secureReceive(Socket socket, byte[] incomingData) {
                    System.out.println("secure receive");
                }

                @Override
                public boolean isServer() {
                    System.out.println("is server");
                    return true;
                }

                @Override
                public InetSocketAddress getSocketAddress() throws UnknownHostException {
                    System.out.println("get socket address ");
                    return new InetSocketAddress(4799);
                }

                @Override
                public void registrationFailed(IOException e) {
                    System.out.println("registartion failed : " + e.getStackTrace());
                }

                @Override
                public void onShutdown() {
                    System.out.println("on shut down");
                }
            };
            reactor.fire();
        } catch (Exception e) {
            System.out.println("exception : " + e.getStackTrace());
            System.exit(0);
        }
    }
}
