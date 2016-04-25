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

###tomcat 双向认证keytool使用

1.生成tomcat服务器证书

```bat
keytool -genkey -v -alias tomcat -keyalg RSA -keystore tomcat.keystore -validity 36500
```

2.生成用户的pkcs12证书

```bat
keytool -genkey -v -alias mykey -keyalg RSA -storetype PKCS12 -keystore client.key.p12
```

3.将用户证书导出cer文件

```bat
keytool -export -alias mykey -keystore client.key.p12 -storetype PKCS12 -storepass password2 -rfc -file client.key.cer
```

4.将服务器证书导出cer文件

```bat
keytool -keystore tomcat.keystore -export -alias tomcat -file tomcat.cer
```

5.将用户的cer证书导入到keystore中

```bat
keytool -import -v -file client.key.cer -keystore tomcat.keystore
```

6.查看keystore中的证书

```bat
keytool -list -keystore tomcat.keystore
```

7.安装服务器的cer证书到受信任的颁发机构里面，将用户的的p12证书导入

8.配置tomcat的server.xml
