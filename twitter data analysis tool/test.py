# -*- coding: utf-8 -*-
"""
Created on Mon Oct 21 11:27:07 2019

@author: SURAJ
"""

from __future__ import division
from __future__ import print_function

import json
import sys
import gzip
import time
import base64
import re
import logging
import requests
from requests_oauthlib import OAuth1, OAuth2
import io
import warnings
from uuid import uuid4
import os


'''########################################################################'''

''' Pre Built '''
''' NOt to Edit '''
try:
    # python 3
    from urllib.parse import urlparse, urlunparse, urlencode, quote_plus
    from urllib.request import __version__ as urllib_version
except ImportError:
    from urlparse import urlparse, urlunparse
    from urllib import urlencode, quote_plus
    from urllib import __version__ as urllib_version

from twitter import (
    __version__,
    _FileCache,
    Category,
    DirectMessage,
    List,
    Status,
    Trend,
    User,
    UserStatus,
)

from twitter.ratelimit import RateLimit

from twitter.twitter_utils import (
    calc_expected_status_length,
    is_url,
    parse_media_file,
    enf_type,
    parse_arg_list)

from twitter.error import (
    TwitterError,
    PythonTwitterDeprecationWarning330,
)

if sys.version_info > (3,):
    long = int  # pylint: disable=invalid-name,redefined-builtin

CHARACTER_LIMIT = 280

# A singleton representing a lazily instantiated FileCache.
DEFAULT_CACHE = object()

logger = logging.getLogger(__name__)


class Api(object):


    DEFAULT_CACHE_TIMEOUT = 60  # cache for 1 minute
    _API_REALM = 'Twitter API'

    def __init__(self,
                 consumer_key=None,
                 consumer_secret=None,
                 access_token_key=None,
                 access_token_secret=None,
                 application_only_auth=False,
                 input_encoding=None,
                 request_headers=None,
                 cache=DEFAULT_CACHE,
                 base_url=None,
                 stream_url=None,
                 upload_url=None,
                 chunk_size=1024 * 1024,
                 use_gzip_compression=False,
                 debugHTTP=False,
                 timeout=None,
                 sleep_on_rate_limit=False,
                 tweet_mode='compat',
                 proxies=None):
        
        

        # check to see if the library is running on a Google App Engine instance
        # see GAE.rst for more information
        if os.environ:
            if 'APPENGINE_RUNTIME' in os.environ.keys():
                # Adapter ensures requests use app engine's urlfetch
                import requests_toolbelt.adapters.appengine
                requests_toolbelt.adapters.appengine.monkeypatch()
                # App Engine does not like this caching strategy, disable caching
                cache = None

        self.SetCache(cache)
        self._cache_timeout = Api.DEFAULT_CACHE_TIMEOUT
        self._input_encoding = input_encoding
        self._use_gzip = use_gzip_compression
        self._debugHTTP = debugHTTP
        self._shortlink_size = 19
        if timeout and timeout < 30:
            warnings.warn("Warning: The Twitter streaming API sends 30s keepalives, the given timeout is shorter!")
        self._timeout = timeout
        self.__auth = None

        self._InitializeRequestHeaders(request_headers)
        self._InitializeUserAgent()
        self._InitializeDefaultParameters()

        self.rate_limit = RateLimit()
        self.sleep_on_rate_limit = sleep_on_rate_limit
        self.tweet_mode = tweet_mode
        self.proxies = proxies

        if base_url is None:
            self.base_url = 'https://api.twitter.com/1.1'
        else:
            self.base_url = base_url

        if stream_url is None:
            self.stream_url = 'https://stream.twitter.com/1.1'
        else:
            self.stream_url = stream_url

        if upload_url is None:
            self.upload_url = 'https://upload.twitter.com/1.1'
        else:
            self.upload_url = upload_url

        self.chunk_size = chunk_size

        if self.chunk_size < 1024 * 16:
            warnings.warn((
                "A chunk size lower than 16384 may result in too many "
                "requests to the Twitter API when uploading videos. You are "
                "strongly advised to increase it above 16384"))

        if (consumer_key and not
           (application_only_auth or all([access_token_key, access_token_secret]))):
            raise TwitterError({'message': "Missing oAuth Consumer Key or Access Token"})

        self.SetCredentials(consumer_key, consumer_secret, access_token_key, access_token_secret,
                            application_only_auth)

        if debugHTTP:
            try:
                import http.client as http_client  # python3
            except ImportError:
                import httplib as http_client  # python2

            http_client.HTTPConnection.debuglevel = 1

            logging.basicConfig()  # you need to initialize logging, otherwise you will not see anything from requests
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

        self._session = requests.Session()

    @staticmethod
    def GetAppOnlyAuthToken(consumer_key, consumer_secret):
        
        """
        Generate a Bearer Token from consumer_key and consumer_secret
        """
        key = quote_plus(consumer_key)
        secret = quote_plus(consumer_secret)
        bearer_token = base64.b64encode('{}:{}'.format(key, secret).encode('utf8'))

        post_headers = {
            'Authorization': 'Basic {0}'.format(bearer_token.decode('utf8')),
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        }

        res = requests.post(url='https://api.twitter.com/oauth2/token',
                            data={'grant_type': 'client_credentials'},
                            headers=post_headers)
        bearer_creds = res.json()
        return bearer_creds


    def SetCredentials(self,
                       consumer_key,
                       consumer_secret,
                       access_token_key=None,
                       access_token_secret=None,
                       application_only_auth=False):
       
        self._consumer_key = consumer_key
        self._consumer_secret = consumer_secret
        self._access_token_key = access_token_key
        self._access_token_secret = access_token_secret

        if application_only_auth:
            self._bearer_token = self.GetAppOnlyAuthToken(consumer_key, consumer_secret)
            self.__auth = OAuth2(token=self._bearer_token)
        else:
            auth_list = [consumer_key, consumer_secret,
                         access_token_key, access_token_secret]
            if all(auth_list):
                self.__auth = OAuth1(consumer_key, consumer_secret,
                                     access_token_key, access_token_secret)

        self._config = None


    def GetHelpConfiguration(self):
        """Get basic help configuration details from Twitter.

        Args:
            None

        Returns:
            dict: Sets self._config and returns dict of help config values.
        """
        if self._config is None:
            url = '%s/help/configuration.json' % self.base_url
            resp = self._RequestUrl(url, 'GET')
            data = self._ParseAndCheckTwitter(resp.content.decode('utf-8'))
            self._config = data
        return self._config


    def GetShortUrlLength(self, https=False):
       
        config = self.GetHelpConfiguration()
        if https:
            return config['short_url_length_https']
        else:
            return config['short_url_length']

    def ClearCredentials(self):
        """Clear any credentials for this instance
        """
        self._consumer_key = None
        self._consumer_secret = None
        self._access_token_key = None
        self._access_token_secret = None
        self._bearer_token = None
        self.__auth = None  # for request upgrade
        
        
    ''' #############################################################################################3'''  
        
        
    '''###################   use below codes to extract data from twitter  ###########'''
        
    def GetUserss(self,
                user_id=None,
                screen_name=None,
                include_entities=False,
                return_json=False):
        
        url = '%s/users/show.json' % (self.base_url)
        parameters = {
            'include_entities': include_entities
        }
        if user_id:
            parameters['user_id'] = user_id
        elif screen_name:
            parameters['screen_name'] = screen_name
        else:
            raise TwitterError("Specify at least one of user_id or screen_name.")

        resp = self._RequestUrl(url, 'GET', data=parameters)
        data = self._ParseAndCheckTwitter(resp.content.decode('utf-8'))

        if return_json:
            return data
        else:
            return User.NewFromJsonDict(data)
        
    
    

    
    def Getfrnd(self,user_id=None,
                screen_name=None,
                cursor=-1,
                count=200,
                skip_status=False,
                include_user_entities=False):
        
        url = '%s/friends/list.json' % (self.base_url)
        parameters = {
            'include_user_entities': include_user_entities
        }
        if user_id:
            parameters['user_id'] = user_id
        elif screen_name:
            parameters['screen_name'] = screen_name
            parameters['skip_status']=skip_status
            parameters['cursor']=cursor
            parameters['count']=count
        else:
            raise TwitterError("Specify at least one of user_id or screen_name.")

        resp = self._RequestUrl(url, 'GET', data=parameters)
        data = self._ParseAndCheckTwitter(resp.content.decode('utf-8'))

        
        return data
    
    def Gettweets(self,
                q=None,
                result_type='mixed',
                count=200,
                include_user_entities=False):
        
        url = '%s/search/tweets.json' % (self.base_url)
        parameters = {
            'include_user_entities': include_user_entities
        }
        
        if q:
            parameters['q'] = q
            parameters['result_type']=result_type
            parameters['count']=count
            
        else:
            raise TwitterError("Specify at least one of user_id or screen_name.")

        resp = self._RequestUrl(url, 'GET', data=parameters)
        data = self._ParseAndCheckTwitter(resp.content.decode('utf-8'))
             
        return data
        
    def Gettweetstest(self,q=None,result_type='mixed',count=200,include_user_entities=False):
        
        f = open('retweeterstest.twt', 'w', encoding='utf-8')
        url = '%s/search/tweets.json' % (self.base_url)
        parameters = {
            'include_user_entities': include_user_entities
            }
        max_id=None
        if q:
             parameters['q'] = q
             parameters['result_type']=result_type
             parameters['count']=count
             parameters['tweet_mode']='extended'
            
        else:
            raise TwitterError("Specify at least one of user_id or screen_name.")
        while True:
            if max_id:
                parameters['max_id']=max_id
            resp = self._RequestUrl(url, 'GET', data=parameters)
            data = self._ParseAndCheckTwitter(resp.content.decode('utf-8'))
            data = data['statuses']
            if len(data) == 0:
                return
            for tweet in data:
                if tweet['id'] == max_id:
                    if len(data) == 1:
                        print('helloo')
                        return
                    else:
                        continue
                if max_id is None:
                    max_id = tweet['id']
                else:
                    max_id=min(max_id, tweet['id']) 
                f.write(tweet['user']['screen_name']+tweet['text']+'\n')
                #else:
        #f.write('%30s %s\n' % (tweet['created_at'], tweet['full_text'].replace('\n', ' ')))

          
        
        
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    '''#############################################################################################''' 
    
    ''' PRE BUILT '''
    '''not to edit below codes'''
    
    
    
    
    
    def SetCache(self, cache):
        """Override the default cache.  Set to None to prevent caching.

        Args:
          cache:
            An instance that supports the same API as the twitter._FileCache
        """
        if cache == DEFAULT_CACHE:
            self._cache = _FileCache()
        else:
            self._cache = cache


    def SetUrllib(self, urllib):
        """Override the default urllib implementation.

        Args:
          urllib:
            An instance that supports the same API as the urllib2 module
        """
        self._urllib = urllib


    def SetCacheTimeout(self, cache_timeout):
        """Override the default cache timeout.

        Args:
          cache_timeout:
            Time, in seconds, that responses should be reused.
        """
        self._cache_timeout = cache_timeout


    def SetUserAgent(self, user_agent):
        """Override the default user agent.

        Args:
          user_agent:
            A string that should be send to the server as the user-agent.
        """
        self._request_headers['User-Agent'] = user_agent


    def SetXTwitterHeaders(self, client, url, version):
        """Set the X-Twitter HTTP headers that will be sent to the server.

        Args:
          client:
             The client name as a string.  Will be sent to the server as
             the 'X-Twitter-Client' header.
          url:
             The URL of the meta.xml as a string.  Will be sent to the server
             as the 'X-Twitter-Client-URL' header.
          version:
             The client version as a string.  Will be sent to the server
             as the 'X-Twitter-Client-Version' header.
        """
        self._request_headers['X-Twitter-Client'] = client
        self._request_headers['X-Twitter-Client-URL'] = url
        self._request_headers['X-Twitter-Client-Version'] = version


    def SetSource(self, source):
        """Suggest the "from source" value to be displayed on the Twitter web site.

        The value of the 'source' parameter must be first recognized by
        the Twitter server.

        New source values are authorized on a case by case basis by the
        Twitter development team.

        Args:
          source:
            The source name as a string.  Will be sent to the server as
            the 'source' parameter.
        """
        self._default_params['source'] = source


    def InitializeRateLimit(self):
        """ Make a call to the Twitter API to get the rate limit
        status for the currently authenticated user or application.

        Returns:
            None.

        """
        _sleep = self.sleep_on_rate_limit
        if self.sleep_on_rate_limit:
            self.sleep_on_rate_limit = False

        url = '%s/application/rate_limit_status.json' % self.base_url

        resp = self._RequestUrl(url, 'GET')  # No-Cache
        data = self._ParseAndCheckTwitter(resp.content.decode('utf-8'))

        self.sleep_on_rate_limit = _sleep
        self.rate_limit = RateLimit(**data)


    def CheckRateLimit(self, url):
        """ Checks a URL to see the rate limit status for that endpoint.

        Args:
            url (str):
                URL to check against the current rate limits.

        Returns:
            namedtuple: EndpointRateLimit namedtuple.

        """
        if not self.rate_limit.__dict__.get('resources', None):
            self.InitializeRateLimit()

        if url:
            limit = self.rate_limit.get_limit(url)

        return limit


    
    
    #///////////////////////////////////////////////////////////////////////////#
    
    
    
    
    
    def _BuildUrl(self, url, path_elements=None, extra_params=None):
        # Break url into constituent parts
        (scheme, netloc, path, params, query, fragment) = urlparse(url)

        # Add any additional path elements to the path
        if path_elements:
            # Filter out the path elements that have a value of None
            filtered_elements = [i for i in path_elements if i]
            if not path.endswith('/'):
                path += '/'
            path += '/'.join(filtered_elements)

        # Add any additional query parameters to the query string
        if extra_params and len(extra_params) > 0:
            extra_query = self._EncodeParameters(extra_params)
            # Add it to the existing query
            if query:
                query += '&' + extra_query
            else:
                query = extra_query

        # Return the rebuilt URL
        return urlunparse((scheme, netloc, path, params, query, fragment))

    def _InitializeRequestHeaders(self, request_headers):
        if request_headers:
            self._request_headers = request_headers
        else:
            self._request_headers = {}

    def _InitializeUserAgent(self):
        user_agent = 'Python-urllib/%s (python-twitter/%s)' % \
                     (urllib_version, __version__)
        self.SetUserAgent(user_agent)

    def _InitializeDefaultParameters(self):
        self._default_params = {}

    @staticmethod
    def _DecompressGzippedResponse(response):
        raw_data = response.read()
        if response.headers.get('content-encoding', None) == 'gzip':
            url_data = gzip.GzipFile(fileobj=io.StringIO(raw_data)).read()
        else:
            url_data = raw_data
        return url_data

    @staticmethod
    def _EncodeParameters(parameters):
        """Return a string in key=value&key=value form.

        Values of None are not included in the output string.

        Args:
          parameters (dict): dictionary of query parameters to be converted into a
          string for encoding and sending to Twitter.

        Returns:
          A URL-encoded string in "key=value&key=value" form
        """
        if parameters is None:
            return None
        if not isinstance(parameters, dict):
            raise TwitterError("`parameters` must be a dict.")
        else:
            params = dict()
            for k, v in parameters.items():
                if v is not None:
                    if getattr(v, 'encode', None):
                        v = v.encode('utf8')
                    params.update({k: v})
            return urlencode(params)

    def _ParseAndCheckTwitter(self, json_data):
        """Try and parse the JSON returned from Twitter and return
        an empty dictionary if there is any error.

        This is a purely defensive check because during some Twitter
        network outages it will return an HTML failwhale page.
        """
        try:
            data = json.loads(json_data)
        except ValueError:
            if "<title>Twitter / Over capacity</title>" in json_data:
                raise TwitterError({'message': "Capacity Error"})
            if "<title>Twitter / Error</title>" in json_data:
                raise TwitterError({'message': "Technical Error"})
            if "Exceeded connection limit for user" in json_data:
                raise TwitterError({'message': "Exceeded connection limit for user"})
            if "Error 401 Unauthorized" in json_data:
                raise TwitterError({'message': "Unauthorized"})
            raise TwitterError({'Unknown error': '{0}'.format(json_data)})
        self._CheckForTwitterError(data)
        return data

    @staticmethod
    def _CheckForTwitterError(data):
        """Raises a TwitterError if twitter returns an error message.

        Args:
            data (dict):
                A python dict created from the Twitter json response

        Raises:
            (twitter.TwitterError): TwitterError wrapping the twitter error
            message if one exists.
        """
        # Twitter errors are relatively unlikely, so it is faster
        # to check first, rather than try and catch the exception
        if 'error' in data:
            raise TwitterError(data['error'])
        if 'errors' in data:
            raise TwitterError(data['errors'])

    def _RequestChunkedUpload(self, url, headers, data):
        try:
            return requests.post(
                url,
                headers=headers,
                data=data,
                auth=self.__auth,
                timeout=self._timeout,
                proxies=self.proxies
            )
        except requests.RequestException as e:
            raise TwitterError(str(e))

    def _RequestUrl(self, url, verb, data=None, json=None, enforce_auth=True):
        """Request a url.

        Args:
            url:
                The web location we want to retrieve.
            verb:
                Either POST or GET.
            data:
                A dict of (str, unicode) key/value pairs.

        Returns:
            A JSON object.
        """
        if enforce_auth:
            if not self.__auth:
                raise TwitterError("The twitter.Api instance must be authenticated.")

            if url and self.sleep_on_rate_limit:
                limit = self.CheckRateLimit(url)

                if limit.remaining == 0:
                    try:
                        stime = max(int(limit.reset - time.time()) + 10, 0)
                        logger.debug('Rate limited requesting [%s], sleeping for [%s]', url, stime)
                        time.sleep(stime)
                    except ValueError:
                        pass

        if not data:
            data = {}

        if verb == 'POST':
            if data:
                if 'media_ids' in data:
                    url = self._BuildUrl(url, extra_params={'media_ids': data['media_ids']})
                    resp = self._session.post(url, data=data, auth=self.__auth, timeout=self._timeout, proxies=self.proxies)
                elif 'media' in data:
                    resp = self._session.post(url, files=data, auth=self.__auth, timeout=self._timeout, proxies=self.proxies)
                else:
                    resp = self._session.post(url, data=data, auth=self.__auth, timeout=self._timeout, proxies=self.proxies)
            elif json:
                resp = self._session.post(url, json=json, auth=self.__auth, timeout=self._timeout, proxies=self.proxies)
            else:
                resp = 0  # POST request, but without data or json

        elif verb == 'GET':
            data['tweet_mode'] = self.tweet_mode
            url = self._BuildUrl(url, extra_params=data)
            resp = self._session.get(url, auth=self.__auth, timeout=self._timeout, proxies=self.proxies)

        else:
            resp = 0  # if not a POST or GET request

        if url and self.rate_limit and resp:
            limit = resp.headers.get('x-rate-limit-limit', 0)
            remaining = resp.headers.get('x-rate-limit-remaining', 0)
            reset = resp.headers.get('x-rate-limit-reset', 0)

            self.rate_limit.set_limit(url, limit, remaining, reset)

        return resp

    def _RequestStream(self, url, verb, data=None, session=None):
        """Request a stream of data.

           Args:
             url:
               The web location we want to retrieve.
             verb:
               Either POST or GET.
             data:
               A dict of (str, unicode) key/value pairs.

           Returns:
             A twitter stream.
        """
        session = session or requests.Session()

        if verb == 'POST':
            try:
                return session.post(url, data=data, stream=True,
                                    auth=self.__auth,
                                    timeout=self._timeout,
                                    proxies=self.proxies)
            except requests.RequestException as e:
                raise TwitterError(str(e))
        if verb == 'GET':
            url = self._BuildUrl(url, extra_params=data)
            try:
                return session.get(url, stream=True, auth=self.__auth,
                                   timeout=self._timeout, proxies=self.proxies)
            except requests.RequestException as e:
                raise TwitterError(str(e))
        return 0  # if not a POST or GET request
    
    
    
    
    
    
'''####################################################################################################'''    
            
''' Calling Scripts '''
''' used to call methods to extract data'''
                      


api = Api(consumer_key='NExcNhjZUCRYDYkQmzaquRFmB'
                  ,consumer_secret='7f74Rar8pboHUSPYbWbHgi7sUZEyHoQ9hLtaUOEd8XLlcITPwE'
                  ,access_token_key='1181963994942230528-RT2tmWlnw1lEhaQeZ3D8ctvorAoKiU'
                  ,access_token_secret='vFhbd2SM7WXrazuDb1PSuYVOvRineITxXmaffjtuhrGXF')
'''screen_name='@narendramodi'
li=api.GetUsersSearch(screen_name)
print(li)

l2=api.Getfollowers(screen_name)
print(l2)'''
#li=api.GetUserss(user_id=None, screen_name='@narendramodi', include_entities=False, return_json=False)
#print(li)
'''l2=api.Getfrnd( user_id=None,screen_name='@narendramodi',cursor=-1,count=200,skip_status=True,include_user_entities=False)
fr=open('@narendramodi.txt','w', encoding="utf-8")
for j in range(len(l2['users'])):
    print(l2['users'][j]['name'])
    fr.write(l2['users'][j]['name'])
fr.close()'''
li=api.Gettweets(q='RT @narendramodi:Selamat kepada Presiden @jokowi atas permulaan masa jabatan Presiden kedua kalinya di Indonesia, tetangga dekat maritim kita. Saya yakin bahwa di bawah kepemimpinannya yang dinamis, persahabatan kita dan Kemitraan Strategis Komprehensif kita akan semakin dalam.',result_type='mixed',count=2,include_user_entities=False)
print(li)
print(len(li['statuses']))
for i in range(len(li['statuses'])):
    print(li['statuses'][i]['user']['screen_name'],li['statuses'][i]['id'])
#api.Gettweetstest(q='RT @narendramodi:Selamat kepada Presiden @jokowi atas permulaan masa jabatan Presiden kedua kalinya di Indonesia, tetangga dekat maritim kita. Saya yakin bahwa di bawah kepemimpinannya yang dinamis, persahabatan kita dan Kemitraan Strategis Komprehensif kita akan semakin dalam.' ,result_type='mixed',count=100,include_user_entities=False)
api.Gettweetstest(q='RT @narendramodi Selamat kepada Presiden @jokowi atas permulaan masa jabatan Presiden kedua kalinya di Indonesia, tetangga dekat maritim kita. Saya yakin bahwa di bawah kepemimpinannya yang dinamis, persahabatan kita dan Kemitraan Strategis Komprehensif kita akan semakin dalam.' ,result_type='mixed',count=100,include_user_entities=False)