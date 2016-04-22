# pkidemo
JCE学习

###tomcat配置jks文件(server.xml)

    `clientAuth`:设置是否双向验证，默认为false，设置为true代表双向验证

    `keystoreFile`:服务器证书文件路径

    `keystorePass`:服务器证书密码

    `truststoreFile`:用来验证客户端证书的根证书，此例中就是服务器证书

    `truststorePass`:根证书密码

```xml
   <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
               maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
               clientAuth="true" sslProtocol="TLS" keystoreFile="D:/github/cs/pkidemo/keystore.jks" keystorePass="password" truststoreFile="D:/github/cs/pkidemo/keystore.jks" truststorePass="password"/>
```
