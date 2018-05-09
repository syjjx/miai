import json
import requests
import os,re,random,string
import hashlib
import time
import base64

from urllib import parse



import logging
_LOGGER = logging.getLogger(__name__)


class xiaomi_tts:

    def __init__(self,user=None,password=None,login_info_dir='../.xiaoai',can_input_capt=True): 
        requests.packages.urllib3.disable_warnings() 
        self._user=user
        self._password=password        
        self.Service_Token=None
        self.deviceIds=None
        self.userId=None
        self._cookies={}
        self._can_input_capt=can_input_capt
        self._can_save_token=True
        self._request=requests.session() 
        self._login_info_dir=login_info_dir
        self._headers={'Host': 'account.xiaomi.com',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'zh-CN,zh;q=0.9'}        
        try:          

            if not os.path.exists(self._login_info_dir):        #判断目录是否存在
                os.makedirs(self._login_info_dir)               #创建目录
            if not os.access(self._login_info_dir,os.W_OK):     #判断目录是否可写
                self._can_save_token=False              
        except IOError as e:
            self._can_save_token=False 
            #Failed to create directory

        if self._can_save_token==True:
            if not self._get_logon_info():
                #没有读取到保存的Token
                self._LoginByPassord()
            else:
                pass
                
        else:
            self._LoginByPassord()#No write permission
            

    @property
    def Service_Token_Cookie(self):
        return self.Service_Token

    @property
    def deviceIds_miai(self):
        return self.deviceIds



    def _LoginByPassord(self):
        if not self._get_sign():
            _LOGGER.warning("get_sign Failed")
        else:
            if not self._serviceLoginAuth2():
                _LOGGER.warning('Request Login_url Failed')
            else:
                if self._serviceLoginAuth2_json['code']==0:
                    #logon success,run self._login_miai()
                    if not self._login_miai():
                        _LOGGER.warning('login miai Failed')
                    else:
                        if not self._get_deviceId():
                            _LOGGER.warning('get_deviceId Failed')                  
                elif self._serviceLoginAuth2_json['code']==87001:
                    if self._can_input_capt==True:
                        self._headers['Cookie']=self._headers['Cookie']+'; pwdToken={}'.format(self._cookies['pwdToken']) 

                        try:                
                            r= self._request.get('https://account.xiaomi.com/pass/getCode?icodeType=login&{}'.format(int(round(time.time() * 1000))),headers=self._headers,timeout=3,cookies=self._cookies,verify=False)         
                            self._cookies['ick']=self._request.cookies.get_dict()['ick'] 
                            if self._can_save_token==False:
                                self._login_info_dir='.' #上一级目录没有写权限,将验证码图片保存到当前目录
                            with open(self._login_info_dir+'/capt.jpg','wb') as f:  
                                f.write(r.content)  
                                f.close() 
                            capt_code = input('请输入验证码:')
                            self._serviceLoginAuth2(capt_code) 
                            if self._serviceLoginAuth2_json['code']==0:
                                if not self._login_miai():
                                    _LOGGER.warning('login miai Failed')
                                else:
                                    if not self._get_deviceId():
                                        _LOGGER.warning('get_deviceId Failed')
                            elif self._serviceLoginAuth2_json['code']==70016:
                                _LOGGER.warning('incorrect password')
                            else:
                                _LOGGER.error(self._serviceLoginAuth2_json)
                        except IOError as e:
                            _LOGGER.warning('No write permission to save capt.jpg')
                        except BaseException as e:
                            _LOGGER.warning(e)     

                    else:
                        _LOGGER.error('HA中不支持验证码登录')

                elif self._serviceLoginAuth2_json['code']==70016:
                    _LOGGER.error('incorrect password')

            



    def _get_logon_info(self):
        try:            
            with open(self._login_info_dir+'/config.json','r',encoding='utf-8') as json_file:
                model=json.load(json_file) 
                json_file.close()
            self.Service_Token=model['Cookie']
            self.deviceIds=model['deviceId']
            return True
        except IOError as e:
            # _LOGGER.error(e) 
            return False


    def _get_sign(self): 
        url = 'https://account.xiaomi.com/pass/serviceLogin?sid=micoapi'
        pattern = re.compile(r'_sign":"(.*?)",')
        try:            
            r = self._request.get(url,headers=self._headers,timeout=3,verify=False)
            # self._cookies['JSESSIONID']=self._request.cookies.get_dict()['JSESSIONID']
            # self._cookies['deviceId']=self._request.cookies.get_dict()['deviceId']
            self._cookies['pass_trace']=self._request.cookies.get_dict()['pass_trace']
            # self._cookies['pass_ua']=self._request.cookies.get_dict()['pass_ua']
            # self._cookies['uLocale']=self._request.cookies.get_dict()['uLocale']
            self._sign=pattern.findall(r.text)[0]
            return True
        except BaseException as e:
            _LOGGER.warning(e) 
            return False 


    def _serviceLoginAuth2(self,captCode=None):
        url='https://account.xiaomi.com/pass/serviceLoginAuth2'
        self._headers['Content-Type']='application/x-www-form-urlencoded'
        self._headers['Accept']='*/*'
        self._headers['Origin']='https://account.xiaomi.com'
        self._headers['Referer']='https://account.xiaomi.com/pass/serviceLogin?sid=micoapi'           
        # self._headers['Cookie']='pass_ua={}; deviceId={}; pass_trace={}; uLocale={}; JSESSIONID={}'.format(self._cookies['pass_ua'],self._cookies['deviceId'],self._cookies['pass_trace'],self._cookies['uLocale'],self._cookies['JSESSIONID'])        
        self._headers['Cookie']='pass_trace={};'.format(self._cookies['pass_trace'])        

        auth_post_data={'_json':'true',
                    '_sign':self._sign,
                    'callback':'https://api.mina.mi.com/sts',
                    'hash':hashlib.md5(self._password.encode('utf-8')).hexdigest().upper(),
                    'qs':'%3Fsid%3Dmicoapi',
                    'serviceParam':'{"checkSafePhone":false}',
                    'sid':'micoapi',
                    'user':self._user}                
   
        try:
            if captCode!=None:
                url='https://account.xiaomi.com/pass/serviceLoginAuth2?_dc={}'.format(int(round(time.time() * 1000)))
                auth_post_data['captCode']=captCode                
                self._headers['Cookie']=self._headers['Cookie']+'; ick={}'.format(self._cookies['ick'])
            r= self._request.post(url,headers=self._headers,data=auth_post_data,timeout=3,cookies=self._cookies,verify=False)
            # _LOGGER.error(self._request.cookies.get_dict()['pwdToken'])
            # if captCode==None:
            self._cookies['pwdToken']=self._request.cookies.get_dict()['pwdToken']
            self._serviceLoginAuth2_json=json.loads(r.text[11:])
            # _LOGGER.error(_serviceLoginAuth2_json)
            return True
        except BaseException as e:
            return False
            _LOGGER.warning(e)  

    def _login_miai(self):
        serviceToken = "nonce={}&{}".format(self._serviceLoginAuth2_json['nonce'],self._serviceLoginAuth2_json['ssecurity'])
        serviceToken_sha1=hashlib.sha1(serviceToken.encode('utf-8')).digest()
        base64_serviceToken = base64.b64encode(serviceToken_sha1)        
        loginmiai_header={'User-Agent': 'MISoundBox/1.4.0,iosPassportSDK/iOS-3.2.7 iOS/11.2.5','Accept-Language': 'zh-cn','Connection': 'keep-alive'}
        url=self._serviceLoginAuth2_json['location']+"&clientSign="+parse.quote(base64_serviceToken.decode())
        try:            
            r = self._request.get(url,headers=loginmiai_header,timeout=3,verify=False)
            if r.status_code==200:
                self._Service_Token=self._request.cookies.get_dict()['serviceToken']
                self.userId=self._request.cookies.get_dict()['userId']
                return True
            else:
                return False
            # return pattern.findall(r.text)[0]
        except BaseException as e :
            _LOGGER.warning(e)
            return False              

    def _get_deviceId(self):
        url='https://api.mina.mi.com/admin/v2/device_list?master=1&requestId=CdPhDBJMUwAhgxiUvOsKt0kwXThAvY'
        get_deviceId_header={'Cookie': 'userId={};serviceToken={}'.format(self.userId,self._Service_Token)}
        try:            
            r = self._request.get(url,headers=get_deviceId_header,timeout=3,verify=False)            
            model={"Cookie": "userId={};serviceToken={}".format(self.userId,self._Service_Token),"deviceId":json.loads(r.text)['data']}
            self.Service_Token=model['Cookie']
            self.deviceIds=model['deviceId']   
            if self._can_save_token!=False:                
                with open(self._login_info_dir+'/config.json','w',encoding='utf-8') as json_file:
                    json.dump(model,json_file,ensure_ascii=False)
                    json_file.close()   
            return True                           
        except BaseException as e :
            _LOGGER.warning(e)
            return False     


    def _text_to_speech(self,text,tts_cookie,deviceIds_miai,num=0,count=0):
        try:   
            url = "https://api.mina.mi.com/remote/ubus?deviceId={}&message=%7B%22text%22%3A%22{}%22%7D&method=text_to_speech&path=mibrain&requestId={}".format(self.deviceIds_miai[num]['deviceID'],parse.quote(text),''.join(random.sample(string.ascii_letters + string.digits, 30)))         
            r = self._request.post(url,headers={'Cookie':tts_cookie},timeout=3,verify=False)
            _LOGGER.info(json.loads(r.text))
            if json.loads(r.text)['message'] == 'Success':
                return True
            else:
                return False
        except IndexError as e:
            _LOGGER.error('你没有那个音箱！')
            return True                
        except AttributeError as e:
            _LOGGER.warning(e)
        except BaseException as e :
            _LOGGER.warning(e)     
            if count>=2:
                return False
            self._text_to_speech(text,tts_cookie,deviceIds_miai,num=num,count=count+1)   

    def player_set_volume(self,volume,tts_cookie,deviceIds_miai,num=0,count=0):
        if volume>100:
            volume=100
        elif volume<0:
            volume=0
        try:   
            url = "https://api.mina.mi.com/remote/ubus?deviceId={}&message=%7b%22volume%22%3a{}%2c%22media%22%3a%22app_ios%22%7d&method=player_set_volume&path=mediaplayer&requestId={}".format(self.deviceIds_miai[num]['deviceID'],int(volume),''.join(random.sample(string.ascii_letters + string.digits, 30)))         
            r = self._request.post(url,headers={'Cookie':tts_cookie},timeout=3,verify=False)
            _LOGGER.info(json.loads(r.text))
            if json.loads(r.text)['message'] == 'Success':
                return True
            else:
                return False
        except IndexError as e:
            _LOGGER.error('你没有那个音箱！')
            return True                
        except AttributeError as e:
            _LOGGER.warning(e)
        except BaseException as e :
            _LOGGER.warning(e)     
            if count>=2:
                return False
            self._text_to_speech(text,tts_cookie,deviceIds_miai,num=num,count=count+1)   

    def player_play_operation(self,operation,tts_cookie,deviceIds_miai,num=0,count=0):

        try:   
            url = "https://api.mina.mi.com/remote/ubus?deviceId={}&message=%7b%22action%22%3a%22{}%22%2c%22media%22%3a%22app_ios%22%7d&method=player_play_operation&path=mediaplayer&requestId={}".format(self.deviceIds_miai[num]['deviceID'],operation,''.join(random.sample(string.ascii_letters + string.digits, 30)))         
            r = self._request.post(url,headers={'Cookie':tts_cookie},timeout=3,verify=False)
            _LOGGER.info(json.loads(r.text))
            if json.loads(r.text)['message'] == 'Success':
                return True
            else:
                return False
        except IndexError as e:
            _LOGGER.error('你没有那个音箱！')
            return True                
        except AttributeError as e:
            _LOGGER.warning(e)
        except BaseException as e :
            _LOGGER.warning(e)     
            if count>=2:
                return False
            self._text_to_speech(text,tts_cookie,deviceIds_miai,num=num,count=count+1)   

if __name__ =='__main__':  
    miid=input('请输入米家账号:')    
    password=input('请输入密码:')
    num=input('请输入音箱编号(从0开始):')  
    cc=xiaomi_tts(miid,password)
    # cc.player_play_operation('play',cc.Service_Token_Cookie,cc.deviceIds_miai,num=int(num))
    if not cc._text_to_speech('Token已生成',cc.Service_Token_Cookie,cc.deviceIds_miai,num=int(num)):
        cc._LoginByPassord()
        cc._text_to_speech('Token已生成',cc.Service_Token_Cookie,cc.deviceIds_miai,num=int(num))

else:
    import voluptuous as vol
    import homeassistant.helpers.config_validation as cv

    CONF_USER = 'miid'
    CONF_PASSWORD = 'password'

    CONF_TO_NUM = 'miai_num'
    ATTR_MESSAGE = 'message'
    # {"message":".","miai_num":"0"}
    ATTR_VOLUME = 'vol'

    DEFAULT_MIAI_NUM = '0'

    DOMAIN = 'hello_miai'

    SERVICE_SCHEMA = vol.Schema({
    vol.Required(ATTR_MESSAGE): cv.string,
    vol.Optional(CONF_TO_NUM): cv.string,
        })

    SERVICE_SCHEMA_FOR_SET_VOLUME = vol.Schema({
    vol.Required(ATTR_VOLUME): cv.string,
    vol.Optional(CONF_TO_NUM): cv.string,
        })

    SERVICE_SCHEMA_FOR_PLAY_OPERATION = vol.Schema({
    vol.Optional(CONF_TO_NUM): cv.string,
        })


    CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Required(CONF_USER): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
            }),
        }, extra=vol.ALLOW_EXTRA)

    def setup(hass, config):
        conf = config.get(DOMAIN, {})
        miid = conf.get(CONF_USER)  
        password = conf.get(CONF_PASSWORD)  
        client = xiaomi_tts(miid, password,login_info_dir=hass.config.path('.xiaoai'),can_input_capt=False)

        def send_message(call):

            to_num = call.data.get(CONF_TO_NUM, DEFAULT_MIAI_NUM)
            message = call.data.get(ATTR_MESSAGE) 
            
                          
            if not client._text_to_speech(message,client.Service_Token_Cookie,client.deviceIds_miai,int(to_num)):
                client._LoginByPassord()
                client._text_to_speech(message,client.Service_Token_Cookie,client.deviceIds_miai,int(to_num))


        def player_set_volume(call):

            to_num = call.data.get(CONF_TO_NUM, DEFAULT_MIAI_NUM)
            vol = call.data.get(ATTR_VOLUME) 
            
                          
            if not client.player_set_volume(int(vol),client.Service_Token_Cookie,client.deviceIds_miai,int(to_num)):
                client._LoginByPassord()
                client.player_set_volume(int(vol),client.Service_Token_Cookie,client.deviceIds_miai,int(to_num))

        def play_operation(call):

            to_num = call.data.get(CONF_TO_NUM, DEFAULT_MIAI_NUM) 
            
                          
            if not client.player_play_operation('play',client.Service_Token_Cookie,client.deviceIds_miai,int(to_num)):
                client._LoginByPassord()
                client.player_play_operation('play',client.Service_Token_Cookie,client.deviceIds_miai,int(to_num))

        def pause_operation(call):

            to_num = call.data.get(CONF_TO_NUM, DEFAULT_MIAI_NUM)
            
                          
            if not client.player_play_operation('pause',client.Service_Token_Cookie,client.deviceIds_miai,int(to_num)):
                client._LoginByPassord()
                client.player_play_operation('pause',client.Service_Token_Cookie,client.deviceIds_miai,int(to_num))


        hass.services.register(DOMAIN, 'send', send_message,
                               schema=SERVICE_SCHEMA)
        hass.services.register(DOMAIN, 'set_vol', player_set_volume,
                               schema=SERVICE_SCHEMA_FOR_SET_VOLUME)
        hass.services.register(DOMAIN, 'play', play_operation,
                               schema=SERVICE_SCHEMA_FOR_PLAY_OPERATION)
        hass.services.register(DOMAIN, 'pause', pause_operation,
                               schema=SERVICE_SCHEMA_FOR_PLAY_OPERATION)                              

        return True