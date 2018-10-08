# python-nettools

ipConflictCheck.py ip冲突检测

dnshades.py

'''
|
|--forwarddns.conf #转发的目的dnsserver(默认是网关)
|
|--domainkey.conf  #转发的域名关键字
|
|--dnshades.py #本脚本



本脚本只是提供 dns proxy 的功能，对domainkey 里面允许的白名单域名或者关键字 进行转发解析，否则 快速返回ServFail给客户端

想到的使用场景

1.孩子电脑环境控制(允许哪些域名可以访问)
本机启用脚本，将本机只设 127.0.0.1 或 本机ip  一个dns,域名解析全部通过 本程序进行。
允许访问的网站域名写入domainkey.conf，正常域名解析就交给 forwarddns.conf 里面的 ip

2.全国各地都用公司内网的dns进行域名解析，但外网解析用的是各地当地的公网dns(各地如果都用一个dns解析外网可能会碰到互联互通的问题，东北的client 去连 上海的机器，可能连不。
各地的client 第一个dns 设置成 dnshades的ip, 备用dns设置成当地的公网dns
公司内网的域名全部转发到内部的dnsserver,当解析外网域名时立即返回ServFail给客户端,
client 收到 ServFail 会立即用备用的当地公网dns进行域名解析。 


待完善功能：
本程序只起了udp 53, clienty dns解析过程中有时也要用到 tcp的 53。


'''
