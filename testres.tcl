load libsysdns0.1.so
puts [::sysdns::resolve _xmpp-server._tcp.gmail.com -type srv]

