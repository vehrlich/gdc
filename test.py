import unittest
import json
import requests
import urlparse
import ConfigParser


# TODO to clear InsecureRequestWarning this scrept needs certificates set up
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class PostUserLogin:
    """
    Class for creating json representation of USER to log in.
    """
    def __init__(self, login, password, remember=0, verify_level=0):
        self.login = login
        self.password = password
        self.remember = remember
        self.verify_level = verify_level

    def to_json(self):
        """
        Prepare dict from it's attributes and returns it's JSON dumps.
        :return: string JSON dumps
        """
        #d = {key: value for (key, value) in iterable}
        s = {'postUserLogin': {key: value for (key, value) in self.__dict__.iteritems()}}
        return json.dumps(s)

class LoginTestCase(unittest.TestCase):
    def getURL(self, url):
        """
        Return url to base url (depend on configuration)
        """
        return urlparse.urljoin(self.config.get('gdc', 'api_url'), url)

    def setUp(self):
        """
        Set up common configuration
        """
        # POST /gdc/account/login
        # load configuration
        self.config = ConfigParser.ConfigParser()
        self.config.read('config_file')
        self.url = self.getURL('gdc/account/login')
        self.headers = {"Content-Type": "application/json",
                        "Accept": "application/json" }

    def test_negative_wrong_credentials(self):
        """
        Tests refuse of login with wrong credentials
        Response should be 400
        """

        # set up user with wrong credentials
        user = PostUserLogin(self.config.get('gdc', 'wrong_username'),
                             self.config.get('gdc', 'wrong_password'))

        # post login and wait for 400 error code
        # TODO handle SSL certificates and remove verify=False
        res = requests.post(self.url, headers=self.headers, data=user.to_json(), verify=False)
        self.assertEquals(res.status_code, 400)

    def test_good_credentials(self):
        """
        Tests successful login with correct credentials.
        Tests retrieving Super Secure Token, Temporary Token and returns profile_id
        Response should be 200 in every stage of authentication

        :return profile_ID and token of logged user
        """
        # set up user with good credentials
        user = PostUserLogin(self.config.get('gdc', 'good_username'),
                             self.config.get('gdc', 'good_password'))

        # TODO handle SSL certificates and remove verify=False
        # post login data
        res = requests.post(self.url, headers=self.headers, data=user.to_json(), verify=False)

        # return this at the end
        profile_id = json.loads(res.content)['userLogin']['profile'].split('/')[-1]

        # check response if contains GDC AuthSST
        self.assertIn('GDCAuthSST', res.cookies)
        self.assertEquals(res.status_code, 200, "User wasn't authenticated. RetCode %s " % res.status_code)
        token = res.cookies['GDCAuthSST']

        # now set up a new request with token and GET to log in
        cookies = {'$Version': "0",
                   'GDCAuthSST': token,
                   '$Path': '/gdc/account'}
        res = requests.get(self.getURL('/gdc/account/token'), headers=self.headers, cookies=cookies, verify=False)
        # after second round response' cookies should contain GDCAuthTT param and response code should be 200
        self.assertIn('GDCAuthTT', res.cookies)
        self.assertEquals(res.status_code, 200, "User wasn't authenticated. RetCode %s " % res.status_code)

        return profile_id, res.cookies['GDCAuthTT']

    def test_logout_authorized(self):
        """"
        Tests logout of logged user. Needs profile_id returned from successful login
        Response should be 204
        """
        # log in and get user profile_id and token
        profile_id, token = self.test_good_credentials()
        headers = self.headers
        headers.pop("Content-Type", None)
        cookies = {'GDCAuthTT': token}

        res = requests.delete(self.getURL('gdc/account/login/%s' % profile_id),
                              headers=self.headers,
                              cookies=cookies,
                              verify=False)

        # different return code has different error message. handling this
        if res.status_code not in [204, 401]:
            msg = ": ".join([json.loads(res.content)['error']['component'],
                             json.loads(res.content)['error']['errorClass'],
                             json.loads(res.content)['error']['message']])
        elif res.status_code is 401:
            msg = "401 Authorization Required"
        else:
            msg = res.status_code

        self.assertEquals(res.status_code, 204, "ERROR %s" % msg)

    def test_negative_logout_not_exists_user(self):
        """"
        Tests logout of not exists user. Profile_id is random id
        Response should be 404
        """
        # log in and get user profile_id and token
        profile_id, token = self.test_good_credentials()
        # change profile_id to non exists one
        profile_id = "asldkajs335l5lsadkfmsd"

        # update headers, remove content type and create cookie with token
        headers = self.headers
        headers.pop("Content-Type", None)
        cookies = {'GDCAuthTT': token}

        res = requests.delete(self.getURL('gdc/account/login/%s' % profile_id),
                              headers=self.headers,
                              cookies=cookies,
                              verify=False)

        # different return code has different error message. handling this
        if res.status_code not in [204, 401]:
            msg = ": ".join([json.loads(res.content)['error']['component'],
                             json.loads(res.content)['error']['errorClass'],
                             json.loads(res.content)['error']['message']])
        elif res.status_code is 401:
            msg = "401 Authorization Required"
        else:
            msg = res.status_code

        self.assertEquals(res.status_code, 404, "ERROR %s" % msg)

    def test_negative_logout_exists_user_by_another(self):
        """"
        Tests logout of exists user by another  exists user.
        Response should be 400
        """
        # set up user with good credentials o user2
        user2 = PostUserLogin(self.config.get('gdc', 'good_username2'),
                              self.config.get('gdc', 'good_password2'))

        # TODO handle SSL certificates and remove verify=False
        # post login data
        res = requests.post(self.url, headers=self.headers, data=user2.to_json(), verify=False)

        # return this at the end
        profile_id2 = json.loads(res.content)['userLogin']['profile'].split('/')[-1]

        # now log in user1
        profile_id, token = self.test_good_credentials()

        # update headers, remove content type and create cookie with token
        headers = self.headers
        headers.pop("Content-Type", None)
        cookies = {'GDCAuthTT': token}
        # try to logout user2 with user1
        res = requests.delete(self.getURL('gdc/account/login/%s' % profile_id2),
                              headers=self.headers,
                              cookies=cookies,
                              verify=False)
        msg = res.status_code
        self.assertEquals(res.status_code, 400, "ERROR %s" % msg)

    def test_negative_logout_exists_user_while_logout(self):
        """"
        Tests logout of exists while logout. Profile_id remains, but there is no token
        Response should be 401
        """
        # log in and get user profile_id and token
        profile_id, token = self.test_good_credentials()

        # update headers, remove content type and create cookie with token
        headers = self.headers
        headers.pop("Content-Type", None)
        cookies = {'GDCAuthTT': token}
        # first logout
        res = requests.delete(self.getURL('gdc/account/login/%s' % profile_id),
                              headers=self.headers,
                              cookies=cookies,
                              verify=False)

        # then try to logout again without token
        res = requests.delete(self.getURL('gdc/account/login/%s' % profile_id),
                              headers=self.headers,
                              verify=False)

        # different return code has different error message. handling this
        # TODO make this msg generating more easy
        if res.status_code not in [204, 401]:
            msg = ": ".join([json.loads(res.content)['error']['component'],
                             json.loads(res.content)['error']['errorClass'],
                             json.loads(res.content)['error']['message']])
        elif res.status_code is 401:
            msg = "401 Authorization Required"
        else:
            msg = res.status_code

        self.assertEquals(res.status_code, 401, "ERROR %s" % msg)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(LoginTestCase)
    unittest.LoginTestCase(verbosity=2).run(suite)

