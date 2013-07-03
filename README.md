jSSL is java convenience library over SSLEngine class to support operations required in SSL. The prj.jSSL.ssl package is
purely for SSL support and unaware of transport. The SSLManager class is responsible for supporting multiple SSL
connections with a help of the ISSLStore class. Developers are encouraged to write the implementation of ISSLStore
themselves. Each SSL connection has one main component - IReaderWriter which the
developers will have to implement according to their needs. Additionally SecureAgent class is provided for developers to
easily write their server implementations.
