# Basic POC of Captive Portal

## PHASE 1
```
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install hostapd
sudo apt-get install dnsmasq
sudo systemctl stop hostapd
sudo systemctl stop dnsmasq
```
```
sudo nano /etc/dhcpcd.conf
```
### append this
```
interface wlan0
static ip_address=192.168.24.1/24
```
then
```
sudo systemctl daemon-reload && sudo systemctl restart dhcpcd
```


```
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
sudo nano /etc/dnsmasq.conf 
```
or
```
sudo cat << EOF > /etc/dnsmasq.conf
bogus-priv
server=/localnet/192.168.24.1
local=/localnet/
interface=wlan0
domain=localnet
dhcp-range=192.168.24.10,192.168.24.254,255.255.255.0,2h
EOF
```

```
sudo nano /etc/hostapd/hostapd.conf
```
or
```
sudo << EOF > /etc/dnsmasq.conf
interface=wlan0
ssid=MyOpenAP
hw_mode=g
channel=6 
auth_algs=1
wmm_enabled=0
EOF
```

```
sudo nano /etc/default/hostapd
```
### append this
```
DAEMON_CONF="/etc/hostapd/hostapd.conf"
```

```
sudo nano /etc/sysctl.conf
```
### uncomment this
```
net.ipv4.ip_forward=1
```
or 
```
sudo echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
```

## PHASE 2 
```
sudo apt-get install iptables-persistent conntrack nginx php php-common php-fpm
```
```
sudo nano /etc/hosts
```
### append this
```
192.168.24.1	hotspot.localnet
::1		localhost ip6-localhost ip6-loopback
fe00::0		ip6-localnet
ff00::0		ip6-mcastprefix
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
```
### actual firewall rules
```
#Turn into root
sudo -i
#Flush all connections in the firewall
iptables -F
#Delete all chains in iptables
iptables -X
#wlan0 is our wireless card. Replace with your second NIC if doing it from a server.
#This will set up our structure
iptables -t mangle -N wlan0_Trusted
iptables -t mangle -N wlan0_Outgoing
iptables -t mangle -N wlan0_Incoming
iptables -t mangle -I PREROUTING 1 -i wlan0 -j wlan0_Outgoing
iptables -t mangle -I PREROUTING 1 -i wlan0 -j wlan0_Trusted
iptables -t mangle -I POSTROUTING 1 -o wlan0 -j wlan0_Incoming
iptables -t nat -N wlan0_Outgoing
iptables -t nat -N wlan0_Router
iptables -t nat -N wlan0_Internet
iptables -t nat -N wlan0_Global
iptables -t nat -N wlan0_Unknown
iptables -t nat -N wlan0_AuthServers
iptables -t nat -N wlan0_temp
iptables -t nat -A PREROUTING -i wlan0 -j wlan0_Outgoing
iptables -t nat -A wlan0_Outgoing -d 192.168.24.1 -j wlan0_Router
iptables -t nat -A wlan0_Router -j ACCEPT
iptables -t nat -A wlan0_Outgoing -j wlan0_Internet
iptables -t nat -A wlan0_Internet -m mark --mark 0x2 -j ACCEPT
iptables -t nat -A wlan0_Internet -j wlan0_Unknown
iptables -t nat -A wlan0_Unknown -j wlan0_AuthServers
iptables -t nat -A wlan0_Unknown -j wlan0_Global
iptables -t nat -A wlan0_Unknown -j wlan0_temp
#forward new requests to this destination
iptables -t nat -A wlan0_Unknown -p tcp --dport 80 -j DNAT --to-destination 192.168.24.1
iptables -t nat -A wlan0_Unknown -p tcp --dport 443 -j DNAT --to-destination 192.168.24.1
iptables -t filter -N wlan0_Internet
iptables -t filter -N wlan0_AuthServers
iptables -t filter -N wlan0_Global
iptables -t filter -N wlan0_temp
iptables -t filter -N wlan0_Known
iptables -t filter -N wlan0_Unknown
iptables -t filter -I FORWARD -i wlan0 -j wlan0_Internet
iptables -t filter -A wlan0_Internet -m state --state INVALID -j DROP
iptables -t filter -A wlan0_Internet -o eth0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t filter -A wlan0_Internet -j wlan0_AuthServers
iptables -t filter -A wlan0_AuthServers -d 192.168.24.1 -j ACCEPT
iptables -t filter -A wlan0_Internet -j wlan0_Global
#allow access to my website :)
iptables -t filter -A wlan0_Global -d andrewwippler.com -j ACCEPT
#allow unrestricted access to packets marked with 0x2
iptables -t filter -A wlan0_Internet -m mark --mark 0x2 -j wlan0_Known
iptables -t filter -A wlan0_Known -d 0.0.0.0/0 -j ACCEPT
iptables -t filter -A wlan0_Internet -j wlan0_Unknown
#allow access to DNS and DHCP
#This helps power users who have set their own DNS servers
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p udp --dport 53 -j ACCEPT
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p tcp --dport 53 -j ACCEPT
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p udp --dport 67 -j ACCEPT
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p tcp --dport 67 -j ACCEPT
iptables -t filter -A wlan0_Unknown -j REJECT --reject-with icmp-port-unreachable
#allow forwarding of requests from anywhere to eth0/WAN
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
#save our iptables
iptables-save > /etc/iptables/rules.v4
```

### Make the HTML Document Root
```
mkdir /usr/share/nginx/html/portal
chown www-data:www-data /usr/share/nginx/html/portal
chmod 755 /usr/share/nginx/html/portal
```
### create the nginx hotspot.conf file
```
cat << EOF > /etc/nginx/sites-available/hotspot.conf
server {
#Listening on IP Address.
#This is the website iptables redirects to
listen       80 default_server;
root         /usr/share/nginx/html/portal;
# For iOS
if ($http_user_agent ~* (CaptiveNetworkSupport) ) {
return 302 http://hotspot.localnet/hotspot.html;
}
#For others
location / {
return 302 http://hotspot.localnet/;
}
}
upstream php {
#this should match value of "listen" directive in php-fpm pool
server unix:/tmp/php7.4-fpm.sock;
server 127.0.0.1:9000;
}
server {
listen       80;
server_name  hotspot.localnet;
root         /usr/share/nginx/html/portal;
index index.html index.htm index.php;
location / {
try_files $uri $uri/ index.php;
}
#Pass all .php files onto a php-fpm/php-fcgi server.
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    }
}
EOF
```

### Enable the website and reload nginx
```
ln -s /etc/nginx/sites-available/hotspot.conf /etc/nginx/sites-enabled/hotspot.conf
```
```
systemctl reload nginx
```
```
sudo nano /usr/share/nginx/html/portal/index.php
```
or
```
sudo cat << EOF > /usr/share/nginx/html/portal/index.php
<!DOCTYPE html>
<?php
// Grant access if the Security code is accurate.
if ($_POST['security_code'] == "andrew-wippler-is-cool") {
// Grab the MAC address
$arp = "/usr/sbin/arp"; // Attempt to get the client's mac address
$mac = shell_exec("$arp -a ".$_SERVER['REMOTE_ADDR']);
preg_match('/..:..:..:..:..:../',$mac , $matches);
$mac2 = $matches[0];
// Reconnect the device to the firewall
exec("sudo rmtrack " . $_SERVER['REMOTE_ADDR']);
$i = "sudo iptables -t mangle -A wlan0_Outgoing  -m mac --mac-source ".$mac2." -j MARK --set-mark 2";
exec($i);
sleep(5);
?> <html>
<head>
<title></title>
</head>
<body>
<h1>You are now free to browse the internet.</h1>
</body> </html>
<?php } else {
  // this is what is seen when first viewing the page
  ?>
  <html>
  <head>
  <title></title>
  </head>
  <body>
  <h1>Authorization Required</h1>
  <p>Before continuing, you must first agree to the <a href="#">Terms of Service</a> and be of the legal age to do that in your selective country or have Parental Consent.
  </p>
  <form method="post" action="index.php">
    <input type="hidden" name="security_code" value="andrew-wippler-is-cool" />
    <input type="checkbox" name="checkbox1" CHECKED /><label for="checkbox1">I Agree to the terms</label><br />
    <input type="submit" value="Connect" />
  </form>
  </body> </html>
<?php } ?>
EOF
```
```
sudo nano /usr/share/nginx/html/portal/hotspot.html
```
or
```
sudo cat << EOF > /usr/share/nginx/html/portal/hotspot.html
 <!--
 <?xml version="1.0" encoding="UTF-8"?>
 <WISPAccessGatewayParam xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://www.wballiance.net/wispr_2_0.xsd">
 <Redirect>
 <MessageType>100</MessageType>
 <ResponseCode>0</ResponseCode>
 <VersionHigh>2.0</VersionHigh>
 <VersionLow>1.0</VersionLow>
 <AccessProcedure>1.0</AccessProcedure>
 <AccessLocation>Andrew Wippler is awesome</AccessLocation>
 <LocationName>MyOpenAP</LocationName>
 <LoginURL>http://hotspot.localnet/</LoginURL>
 </Redirect>
 </WISPAccessGatewayParam>
 -->
EOF
```
```
sudo nano  /usr/share/nginx/html/portal/kick.php
```
or
```
sudo cat << EOF > /usr/share/nginx/html/portal/kick.php
<?php
// get the user IP address from the query string
$ip = $_REQUEST['ip'];

// this is the path to the arp command used to get user MAC address 
// from it's IP address in linux environment.
$arp = "/usr/sbin/arp";

// execute the arp command to get their mac address
$mac = shell_exec("sudo $arp -an " . $ip);
preg_match('/..:..:..:..:..:../',$mac , $matches);
$mac = @$matches[0];

// if MAC Address couldn't be identified.
if( $mac === NULL) {
  echo "Error: Can't retrieve user's MAC address.";
  exit;
}
print_r($matches);

// Delete it from iptables bypassing rules entry.
while( $chain = shell_exec("sudo iptables -t mangle -L | grep ".strtoupper($mac) ) !== NULL ) {
 echo  exec("sudo iptables -D internet -t mangle -m mac --mac-source ".strtoupper($mac)." -j RETURN");
}
// Why in this while loop?
// Users may have been logged through the portal several times. 
// So they may have chances to have multiple bypassing rules entry in iptables firewall.

// remove their connection track.
echo exec("sudo rmtrack " . $ip); // remove their connection track if any
echo "Kickin' successful.";
?>
EOF
```
```
sudo nano /usr/bin/rmtrack
```
### add this inside, using cat fails
```
/usr/sbin/conntrack -L \
  |grep $1 \
  |grep ESTAB \
  |grep 'dport=80' \
  |awk \
      "{ system(\"conntrack -D --orig-src $1 --orig-dst \" \
          substr(\$6,5) \" -p tcp --orig-port-src \" substr(\$7,7) \" \
          --orig-port-dst 80\"); }"
```
```
sudo visudo
```
### append this
```
www-data ALL=NOPASSWD: /usr/sbin/arp
www-data ALL=NOPASSWD: /usr/bin/rmtrack [0-9]*.[0-9]*.[0-9]*.[0-9]*
www-data ALL=NOPASSWD: /sbin/iptables, /usr/bin/du
www-data ALL=NOPASSWD: /sbin/iptables -t mangle -L | grep ??\:??\:??\:??\:??\:??
www-data ALL=NOPASSWD: /sbin/iptables -t mangle -A wlan0_Outgoing  -m mac --mac-source ??\:??\:??\:??\:??\:?? -j MARK --set-mark 2
www-data ALL=NOPASSWD: /sbin/iptables -t mangle -D wlan0_Outgoing  -m mac --mac-source ??\:??\:??\:??\:??\:?? -j MARK --set-mark 2
```

## USEFUL CMD
```
sudo iptables -L -t mangle --line-numbers
sudo /usr/bin/getusr
  sudo iptables -L -t mangle | GREP $1 
nginx -t
```

## GOTCHAS
### Wifi not working
```
rfkill list all
sudo rfkill unblock all
sudo ip link set wlan0 up
sudo iface wlan0 up
```
then
```
sudo systemctl restart dnsmasq
sudo systemctl restart hostapd
```


