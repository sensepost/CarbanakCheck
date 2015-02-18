# CarbanakCheck

Check squid logs for possible Carbanak malware.

To communicate with its C2 server, Carbanak uses the HTTP protocol with RC2+Base64 encryption, adding additional characters not included in Base64. It also inserts strings with different extensions (.gif,.htm, etc.) at random locations in the HTTP request [1].

Our script looks at GET requests, and if there are no English words in the GET it marks it has suspicous. We can't directly identify Base64 as there are custom characters and random file extensions included.

[1] https://securelist.com/files/2015/02/Carbanak_APT_eng.pdf
