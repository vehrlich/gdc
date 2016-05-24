import unittest
import json
import requests
import urlparse
import base64


# easy use of settings (could be moved into standalone config file)
settings = {
    'api_url' : 'https://secure.gooddata.com',
    'good_credentials': ('', ''),
    'wrong_credentials': ('this_is_bad_name', 'this_is_bad_password')
}

class PostUserLogin:
    """
    class for post user data. Name of class is used in request JSON body

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
    def setUp(self):
        # POST /gdc/account/login
        self.url = urlparse.urljoin(settings['api_url'], '/gdc/account/login')
        self.headers = {"Content-Type": "application/json",
                        "Accept": "application/json" }

    def test_wrong_credentials(self):
        """
        Return code is 400 with wrong credentials.
        """
        user = PostUserLogin(settings['wrong_credentials'][0],
                             settings['wrong_credentials'][1])
        req = requests.post(self.url, headers=self.headers, data=user.to_json())
        self.assertEquals(req.status_code, 400)

    @unittest.skip("Check where is mistake")
    def test_good_credentials(self):
        """
        Return code is 200 when user is authenticated and it returns it's profile ID
        """
        user = PostUserLogin(settings['good_credentials'][0],
                             settings['good_credentials'][1])
        req = requests.post(self.url, headers=self.headers, data=user.to_json())
        print(req.request)
        print(req.headers)
        print(req.cookies['GDCAuthSST'])
        # now failing as 'wrong credentials' with 401.
        # But API docs says only 200, 403 and 400 are only possible response codes
        # TODO find out where is problem
        self.assertEquals(req.status_code, 200, "User wasn't authenticated. RetCode %s " % req.status_code)

    @unittest.skip("WOrk in progress")
    def test_logout_authorized(self):
        """"
        If user is authenticated response header contains it's super-secured-token. This is used for for auth phase 2
        """
        user = PostUserLogin(settings['good_credentials'][0],
                             settings['good_credentials'][1])
        req = requests.post(self.url, headers=self.headers, data=user.to_json())
        with self.assertRaises(KeyError):
            profile_id = json.loads(req.content)['userLogin']['profile']

            self.assertEquals(req.status_code, 200, "PASS User was authenticated.")

if __name__ == '__main__':
    unittest.main()