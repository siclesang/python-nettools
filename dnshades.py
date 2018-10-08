#coding=utf-8
import SocketServer
import os,platform,re,time
from scapy.layers.dns import *

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

2.全国各地都用公司内网的dns进行域名解析，但外网解析用的是各地当地的公网dns(各地如果都用一个dns解析外网可能会碰到互联互通的问题，东北的client 去连 上海的机器，可能连不上)。
各地的client 第一个dns 设置成 dnshades的ip, 备用dns设置成当地的公网dns
公司内网的域名全部转发到内部的dnsserver,当解析外网域名时立即返回ServFail给客户端,
client 收到 ServFail 会立即用备用的当地公网dns进行域名解析。 


待完善功能：
本程序只起了udp 53, clienty dns解析过程中有时也要用到 tcp的 53。


'''




def forwardto():
    '''
    默认转发到 网关，也可以在脚本同级目录 forwarddns.conf 中填写 nameserver ip，目前forwarddns.conf支持第一行一个 dns ip
    '''
    pwd=os.path.split(os.path.realpath(__file__))[0]
    fdnsfile=pwd+"/forwarddns.conf"
    if os.path.isfile(fdnsfile) and os.path.getsize(fdnsfile) != 0 :
        f=open(fdnsfile,'r')
        gw=f.read()
        f.close()
        return gw.strip()
    else:
        if re.search('linux',platform.platform(),re.IGNORECASE):
            gw=os.popen("route -n|grep UG|awk '{print $2}'").read()
        if re.search('windows',platform.platform(),re.IGNORECASE):
            cmd=u'route print 0.0.0.0|findstr "0.0.0.0"'
            gw=os.popen(cmd.encode('gbk')).read().split()[2]
            os.system("echo " + gw.strip()+ " >> "+fdnsfile)
        return gw.strip()


class My_server(SocketServer.BaseRequestHandler):
    '''
    data=self.request[0],client_address=self.client_address, socket=self.request[1]
    '''
    def handle(self):
        data=self.request[0]
        client_addr=self.client_address
        server=self.request[1]  

        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_addr=(forwardserver,53)
        forward_socket.sendto('',forward_addr)
  
        try:
            dnspkg=DNS(data)
            dm=dnspkg.qd.qname #请求解析的域名
            rtype=dnspkg.qd.qtype #请求解析的记录类型           
        except :
            server.sendto(data,client_addr)
        else:        
            #dm=dnspkg.qd.qname
            #rtype=dnspkg.qd.qtype
        
            print "-------------request domain:"+dm+" from "+client_addr[0]+" "+time.strftime('%Y-%m-%d %H:%M:%S')
            if  rtype==12: #如果进行的是反向解析就直接转发
                print dm+"forward to "+forwardserver
                self.udpforward(forward_socket,forward_addr,data,client_addr,server)            
            else:   
                if self.checkdmkey(dm) :
                    print dm+"forward to "+forwardserver
                    self.udpforward(forward_socket,forward_addr,data,client_addr,server)
                else:
                    print "deny "+dm
                    self.proc(data,client_addr,dnspkg,server)
        
    def proc(self,data,client_addr,dnspkg,server):
        if not data: return
        dnspkg.rcode=2 #返回ServFail
        dnspkg.qr=1 #表示响应报文
        server.sendto(bytes(dnspkg),client_addr)
        print "send ServFail to "+client_addr[0]
        print "-------------"
        
    def udpforward(self,forward_socket,forward_addr,data,client_addr,server):
        '''
        数据转发
        '''
        forward_socket.sendto(data,forward_addr)
        fdata, sender_address = forward_socket.recvfrom(1024)
        server.sendto(fdata,client_addr)
        print "forward status ok"
        print "-------------"
        
    def checkdmkey(self,dm):
        '''
        判断 domainkey.conf 中的关键词 是否在 要求解析的 域名里面
        例如 domainkey.conf 有 baidu.com  ,那么 如果解析的域名是 xxx.baidu.com ,则返回True
        '''
        for i in domainkey:
            if i in dm :
                return True
        return False
                
        
        


if __name__ == '__main__':
    pwd=os.path.split(os.path.realpath(__file__))[0]
    dk=open(pwd+"/domainkey.conf",'r')
    domainkey=dk.read().split()
    dk.close()
    print domainkey    
    
    forwardserver=forwardto()
    
    ip_port =('0.0.0.0',53)
    obj =SocketServer.ThreadingUDPServer(ip_port,My_server)
    obj.serve_forever()
