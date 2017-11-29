# DNS-Proxy
DNS proxy (TCP with UDP) + Http Proxy 

Steps for execution 
1.compile DNS-Proxy/socket_adv_raw/src/socket_adv_raw.cpp
2.run the generated binary file.
3.Request a domain by using UDP packet. example UDP data= www.google.com
4.Reply from DNS proxy consists of two IP addresses obtained form 8.8.8.8 and 208.67.222.123
5.To make a DNS request follow step 1 and 2 then execute the java program present in the folder httpProxy file name DNSModule.java
