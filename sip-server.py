import socket
import hashlib # hash MD5

UDP_IP = '127.0.0.1'
UDP_PORT = 5060
PASSWORD = '1234sssFFF1234'
METHODS = ['PRACK', 'INVITE', 'ACK', 'BYE', 'CANCEL', 'UPDATE', 'INFO', 'SUBSCRIBE', 'NOTIFY', 'REFER', 'MESSAGE', 'OPTIONS', 'REGISTER']

HASH_PASSWORD = hashlib.md5(PASSWORD.encode()).hexdigest()

class ListClients:
    _list_client = []
    def __init__(self):
        pass

    def parse_message(self, message):
        print('Parse message:')
        _method = ''
        _user = ''
        if isinstance(message, list):
            _t_rec = {}
            for data_i in data_a:
                if data_i == '' :
                    # Конец заголовка
                    break
                if data_i.find(' ') != -1 :
                    key = data_i[: data_i.find(' ')]
                    value = data_i[data_i.find(' ')+1 :]
                    #print(key)
                    # Возможно это Тип заголовка
                    if key in METHODS :
                        _method = key
                        #print('VALUE: %s ' % value)
                        _t_rec['method'] = key
                        _t_rec['connect'] = value
                    else:
                        key = key.replace(':','')
                        _t_rec[key] = value
                        if key == 'To' :
                            _user = value
                #print(data_i)
            self._list_client += [_t_rec]
        else:
            print('MESSAGE: \n\r %s ' % message)
        print(self._list_client)
        return _method, _user

    def get_message(self, method, user_to):
        """ SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 192.168.5.66:34840;branch=z9hG4bKPj9d90888506004eecb0711abd155c38d3;received=5.59.143.41;rport=34840
From: "1111" <sip:1111@195.133.201.27>;tag=69e1902db56f4bda8dd15905c499d603
To: "1111" <sip:1111@195.133.201.27>;tag=as444a3570
Call-ID: 6cd264b66fd9445c9ca6cac42913c883
CSeq: 26142 REGISTER
Server: Asterisk PBX 13.18.3~dfsg-1ubuntu4
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
Supported: replaces, timer
WWW-Authenticate: Digest algorithm=MD5, realm="asterisk", nonce="7491712d"
Content-Length: 0


REGISTER sip:195.133.201.27 SIP/2.0
Via: SIP/2.0/UDP 192.168.5.66:34840;branch=z9hG4bKPj1b7cef6441ef4d7eae1eb10627751c0d
Max-Forwards: 70
From: "1111" <sip:1111@195.133.201.27>;tag=69e1902db56f4bda8dd15905c499d603
To: "1111" <sip:1111@195.133.201.27>
Call-ID: 6cd264b66fd9445c9ca6cac42913c883
CSeq: 26143 REGISTER
User-Agent: MicroSIP/3.19.29
Contact: <sip:1111@5.59.143.41:34840;ob>
Expires: 300
Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS
Authorization: Digest username="1111", realm="asterisk", nonce="7491712d", uri="sip:195.133.201.27", response="24a964c63acc6e3bdf5204b0e2780ccf", algorithm=MD5
Content-Length:  0
    """
        # find user
        user = {}
        message = []
        for user_s in self._list_client :
            if user_s['To'] == user_to :
                user = user_s
                break

        if method == 'REGISTER' :
            message = ['SIP/2.0 401 Unauthorized']
            for key_t in user.keys() :
                print(key_t)
                if key_t != 'method' and key_t != 'connect' \
                    and  key_t != 'Allow' \
                    and  key_t != 'User-Agent' \
                    and isinstance(key_t , str) :
                    message += [ key_t + ': '+user[key_t]]
            message += ['Server: Asterisk PBX 13.18.3~dfsg-1ubuntu4']
            message += ['Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE']
            message += ['Supported: replaces, timer']
            message += ['WWW-Authenticate: Digest algorithm=MD5, realm="asterisk", nonce="7491712d"']
            pass

        return '\r\n'.join(message)  + '\r\n\r\n'

        pass

def addUser(_user, _port, _callId, _realm, _nonce, _userAgent):
    _user = {
        'user':_user,
        'port':_port,
        'callid':_callId,
        'realm':_realm,
        'nonce':_nonce,
        'userAgent':_userAgent
    }
    return _user
    pass


def hash_auth():
    pass

# ==== main ====
print(HASH_PASSWORD)
sock = socket.socket(socket.AF_INET,    # Internet
                    socket.SOCK_DGRAM)  # UDP

sock.bind((UDP_IP,UDP_PORT))

list_clients = ListClients()
userList = []

while True:
    data,addr = sock.recvfrom(1024)
    final_list = []

    data_a = data.decode("utf-8").split('\r\n')
    method, user = list_clients.parse_message(data_a)
    if method == 'REGISTER' :
        print('register %s' % user)
        SIP_MESSAGE = list_clients.get_message('REGISTER', user).encode()
    else:
        break
    #print("receivd message: {}".format(addr))
    #print('data:{}'.format(data_a))
    #_from = ''
    #_userAgent = ''
    #_callid = ''
    #for data_i in data_a:
    #    header = data_i.split(': ')
    #    if len(header) > 1:
    #        if header[0] == 'From':
    #            _from = header[1]
    #        elif header[0] == 'Call-ID':
    #            _callid = header[1]
    #        elif header[0] == 'User-Agent':
    #            print(header[1])
    #            _userAgent = header[1]
    #
    #        item = {
    #            header[0] : header[1]
    #        }
    #        final_list.append(item)
    #    else:
    #        print(data_i)
    #print(final_list)
    #userList.append(addUser(_from,addr,_callid,'','',_userAgent))
    #print("receivd message: {}".format(userList))
    #SIP_MESSAGE = b''
    #print(SIP_MESSAGE)
    sock.sendto(SIP_MESSAGE, addr)

    pass

pass
