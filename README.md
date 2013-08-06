jSSL is java convenience library over SSLEngine class to support operations required in SSL. The prj.jSSL.ssl package is
purely for SSL support and unaware of transport. The SSLManager class is responsible for supporting multiple SSL
connections with the help of the ISSLStore class. Developers are encouraged to write the implementation of ISSLStore
themselves. Each SSL connection has one main component - IReaderWriter which the
developers will have to implement according to their needs. Additionally SecureAgent class is provided for developers to
easily write their server implementations.
This lib basically take care of conditions if the SSLEngine is not able wrap/unwrap certain data. Mostly this happens
because of buffer size restrictions and the fact that SSLEngine consumes complete SSL/TLS packets only. There is not
threading in this lib and it is up to the user to do this preferably over the lib. In case, you choose to modify the
library, please make sure that SSL/TLS packets are received in order.

NOTE : Work is in progress. The initial first commit is working fine however the subsequent commits are buggy/incomplete.
