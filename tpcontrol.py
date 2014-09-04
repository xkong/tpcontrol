#!/usr/bin/env python
# coding: utf-8
#
# xiaoyu <xiaokong1937@gmail.com>
#
# 2014/08/20
#
# Tplink router control.
"""Flow control tool for tplink-r478

"""
import hashlib
import unittest
import re
import random

import requests
from bs4 import BeautifulSoup as bs
import dict4ini


class TpLoginError(Exception):
    pass


class BaseTpControl(object):
    def __init__(self, username, password, stand_flow_up=256,
                 stand_flow_down=3072,
                 white_list=[],
                 host='192.168.1.1'):
        """
        Login to tplink router.
        """
        self.username = username
        self.password = password
        time_init = 5000  # in 5000 ms
        self.stand_flow_up = stand_flow_up * time_init
        self.stand_flow_down = stand_flow_down * time_init
        self.white_list = white_list
        self.host = host

        self.nonce = ''  # No once, random str.
        self.headers = {}
        self.cookies = ''
        self._done()
        self._set_opener()

    def _done(self):
        self.static_info_html = ''  # Html from static_info page.
        self.statics_data = {}
        self.isLoggedIn = False
        self.arp_info = {}
        self.overflowed = []

    def _set_opener(self):
        """
        Set request headers.
        """
        self.headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': 'http://%s/logon/logon.htm' % self.host,
            'Connection': 'keep-alive',
            'Host': self.host,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/'
                          '537.36 (KHTML, like Gecko) Chrome/30.0.1599.'
                          '101 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def login(self):
        base_url = 'http://%s/' % self.host
        resp = self._request(base_url)
        if resp.status_code == 200:
            self.cookies = resp.cookies
            self.nonce = self.cookies['COOKIE']
        login_url = 'http://%s/logon/loginJump.htm' % self.host
        encode_ = '%s:%s:%s' % (self.username, self.password, self.nonce)
        encoded = '%s:%s' % (self.username, hashlib.md5(encode_).hexdigest())
        params = {
            'encoded': encoded,
            'nonce': self.nonce,
            'URL': '../logon/loginJump.htm'
        }
        resp = self._request(login_url, data=params)
        if self.username in resp.content:
            confirm_url = 'http://%s/logon/loginConfirm.htm' % self.host
            self._request(confirm_url)
            self.isLoggedIn = True
            return 200

        magic_str = '''location.href="../userRpm/Index.htm";</'''
        if magic_str in resp.content:
            self.isLoggedIn = True
            return 200

        raise TpLoginError

    def getStaticInfo(self):
        """
        Get system static.
        """
        if not self.isLoggedIn:
            self.login()
        static_url = 'http://%s/userRpm/System_Statics.htm' % self.host
        params = {
            'btn_refresh': 'btn_refresh',
            'comindex': '0',
            'direct': '0',
            'interface': '1',
        }
        resp = self._request(static_url, params=params)
        self.static_info_html = resp.content
        return resp.status_code

    def parseStaticInfo(self):
        """
        Parse Static info.
        """
        if not self.static_info_html:
            self.getStaticInfo()
        data = self._get_array(self.static_info_html)
        results = {}
        for i in range(len(data)/10):
            snippet = data[10 * i: 10 * (i + 1)]
            ip = snippet[0].replace('"', '')
            results[ip] = snippet[1:10]
        self.statics_data = results
        return results

    def parseFlow(self):
        """
        Parse ip-flow from self.statics_data
        """
        if not self.statics_data:
            self.parseStaticInfo()
        overflowed = []
        for ip, ip_data in self.statics_data.iteritems():
            byte_flow_up = int(ip_data[7])
            byte_flow_down = int(ip_data[8])
            if (byte_flow_up >= self.stand_flow_up or
                    byte_flow_down >= self.stand_flow_down):
                overflowed.append(ip)
            for ip in overflowed:
                if ip in self.white_list:
                    overflowed.remove(ip)
        self.overflowed = overflowed
        return overflowed

    def get_mac_by_ip(self, ip):
        """
        Get mac by ip.
        """
        params = {
            'txt_scan_ips': ip,
            'txt_scan_ipe': ip,
            'btn_begin_scan': '开始扫描'
        }
        arp_scan_url = 'http://%s/userRpm/ARPScan.htm' % self.host
        resp = self._request(arp_scan_url, params=params)
        self._parseArpInfo(resp.content)
        return resp

    def get_arp_info(self):
        """
        Get arp info.
        """
        arp_url = 'http://%s/userRpm/ARPList.htm' % self.host
        resp = self._request(arp_url)
        self._parseArpInfo(resp.content, magic='60')
        return resp

    def _parseArpInfo(self, html, magic='192'):
        results = {}
        data = self._get_array(html, magic)
        for i in range(len(data) / 4):
            snippet = data[4 * i: 4 * (i + 1)]
            ip = snippet[0].replace('"', '')
            results[ip] = snippet[1].replace('"', '')
        self.arp_info.update(results)
        return self.arp_info

    def _get_array(self, html, magic='192'):
        """
        We use this to parse javascript arrays from html source.
        """
        soup = bs(html)
        scripts = soup.find_all(text=re.compile('Array\(\n"%s' % magic))
        if not scripts:
            return
        script = scripts[0].replace('\n', '')
        array = re.findall('\(.*?\)', script)
        if not array:
            return
        data = array[0].replace('(', '').replace(')', '').split(',')
        return data

    def _add_mac_filter(self, mac, ip=''):
        """
        Add mac to blacklist.
        """
        mac_filter_url = 'http://%s/userRpm/Mac_filter.htm' % self.host
        params = {
            'txt_mac_addr': mac,
            'txt_macf_info': ip,
            'btn_add': '新增',
            'option': 'Add',
            'select': '-1',
            'rand_key': random.randint(10000000, 99999999)
        }
        resp = self._request(mac_filter_url, params=params)
        return resp

    def logout(self):
        logout_url = 'http://%s/logon/logout.htm' % self.host
        resp = self._request(logout_url)
        return resp.status_code

    def _request(self, url=None, method=None, headers=None, files=None,
                 data=None, params=None, auth=None, cookies=None,
                 hooks=None, verify=False):
        """ Requests """
        headers = self.headers or headers
        cookies = self.cookies or cookies
        method = 'GET' if data is None else 'POST'

        # Proxy for requests, used for http_debug.
        # Note: by this way, you can use debug tool after its proxy set
        # to 192.168.1.122:8888 (like fiddler2 ).
        # Default: None.
        http_debug = False

        if http_debug:
            http_proxy = 'http://192.168.1.122:8888'
            https_proxy = 'http://192.168.1.122:8888'
            proxyDict = {'http': http_proxy,
                         'https': https_proxy}
        else:
            proxyDict = None

        if method == 'GET':
            resp = requests.get(url, params=params, headers=headers,
                                cookies=cookies, verify=verify,
                                proxies=proxyDict)
        else:
            resp = requests.post(url, params=params, data=data,
                                 headers=headers, cookies=cookies,
                                 verify=verify, files=files,
                                 proxies=proxyDict)
        return resp


class TpContrl(BaseTpControl):
    def __init__(self):
        dict4ini_ = dict4ini.DictIni('tpconfig.ini')
        self.options = dict4ini_.commen
        super(TpContrl, self).__init__(**self.options)

    def doBlock(self):
        """
        Block ips in self.overflowed
        """
        self.parseFlow()
        self.get_arp_info()
        for ip in self.overflowed:
            q = raw_input("Will block [%s: %s], proceed or cancel?" %
                          (ip, self.statics_data[ip]))
            if q == 'c':
                continue
            if ip not in self.arp_info:
                self.get_mac_by_ip(ip)
            mac = self.arp_info[ip]
            self._add_mac_filter(mac, ip)
            print 'ip: %s [%s] blocked' % (ip, mac)
        self._done()
        return 200


class TpCtrlTestCase(unittest.TestCase):
    def setUp(self):
        self.tp = TpContrl()
        self.tp.login()

    @unittest.skip('Test only first login.')
    def test_login(self):
        self.assertEqual(self.tp.login(), 200)

    @unittest.skip('Test only first logout.')
    def test_logout(self):
        self.assertEqual(self.tp.logout(), 200)

    @unittest.skip('Skipped')
    def test_getStaticInfo(self):
        self.assertEqual(self.tp.getStaticInfo(), 200)

    @unittest.skip('Skipped')
    def test_getIndex(self):
        self.assertEqual(self.tp.getIndex(), 200)

    @unittest.skip('Skipped')
    def test_parseStatic(self):
        self.assertEqual(isinstance(self.tp.parseStaticInfo(), dict), True)

    @unittest.skip('Skipped')
    def test_parseFlow(self):
        self.assertEqual(
            isinstance(self.tp.parseFlow(), list),
            True)

    @unittest.skip('Skipped')
    def test_get_mac_by_ip(self):
        self.assertEqual(self.tp.get_mac_by_ip('192.168.1.254').status_code,
                         200)

    @unittest.skip('Skipped')
    def test_get_arp_info(self):
        self.assertEqual(self.tp.get_arp_info().status_code,
                         200)

    @unittest.skip('Skipped')
    def test_filter_mac(self):
        mac = '44-09 - - - -'
        self.assertEqual(self.tp._add_mac_filter(mac, '165').status_code,
                         200)

    def test_doBlock(self):
        self.assertEqual(self.tp.doBlock(), 200)

    def tearDown(self):
        self.tp.logout()

if __name__ == '__main__':
    unittest.main()
