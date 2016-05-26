import unittest
import json
import requests
import urlparse
import ConfigParser

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

    def test_wrong_credentials(self):
        """
        Tests refuse of login with wrong credentials
        """

        # set up user with wrong credentials
        user = PostUserLogin(self.config.get('gdc', 'wrong_username'),
                             self.config.get('gdc', 'wrong_password'))

        # post login and wait for 400 error code
        # TODO handle SSL certificates and remove verify=False
        req = requests.post(self.url, headers=self.headers, data=user.to_json(), verify=False)
        self.assertEquals(req.status_code, 400)

    def test_good_credentials(self):
        """
        Tests successful login with correct credentials.
        Tests retrieving Super Secure Token, Temporary Token and returns profile_id

        :return profile_ID of logged user
        """
        # set up user with good credentials
        user = PostUserLogin(self.config.get('gdc', 'good_username'),
                             self.config.get('gdc', 'good_password'))

        # TODO handle SSL certificates and remove verify=False
        # post login data
        req = requests.post(self.url, headers=self.headers, data=user.to_json(), verify=False)

        #return this at the end
        profile_id = json.loads(req.content)['userLogin']['profile'].split('/')[-1]

        # check response if contains GDC AuthSST
        self.assertIn('GDCAuthSST', req.cookies)
        self.assertEquals(req.status_code, 200, "User wasn't authenticated. RetCode %s " % req.status_code)
        token = req.cookies['GDCAuthSST']

        # now set up a new request with token and GET to log in
        cookies = {'$Version': "0",
                   'GDCAuthSST': token,
                   '$Path': '/gdc/account'}
        req = requests.get(self.getURL('/gdc/account/token'), headers=self.headers, cookies=cookies, verify=False)
        # after second round response' cookies should contain GDCAuthTT param and response code should be 200
        self.assertIn('GDCAuthTT', req.cookies)
        self.assertEquals(req.status_code, 200, "User wasn't authenticated. RetCode %s " % req.status_code)

        req = requests.delete(self.getURL('gdc/account/login/%s' % profile_id),
                              headers=self.headers, verify=False)
        return profile_id, req.cookies['GDCAuthTT']

    def test_logout_authorized(self):
        """"
        Tests logout of logged user. Needs profile_id returned from successful login
        """
        profile_id, token = self.test_good_credentials()

        #cookies = {'GDCAuthTT': token2}

        req = requests.delete(self.getURL('gdc/account/login/%s' % profile_id),
                              headers=self.headers,
                              #cookies=cookies,
                              verify=False)

        self.assertEquals(req.status_code, 200, "Response status code: %s" % req.status_code)

    def test_logout_unauthorized(self):
        """"
        Tests logout of not logged user. Profile id is random text
        """
        profile_id = "asldkajs335l5lsadkfmsd"
        req = requests.delete(self.getURL('gdc/account/login/%s' % profile_id),
                              headers=self.headers, verify=False)
        self.assertEquals(req.status_code, 404, "Response status code: %s" % req.status_code)

if __name__ == '__main__':
    unittest.main()

