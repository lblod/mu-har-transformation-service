import urlparse

# dpkt.http is buggy, so we use our modified replacement
from .. import dpkt_http_replacement as dpkt_http
import message as http
from .. import settings
from ..mediatype import MediaType
from response import Response

class Request(Response):
    '''
    HTTP request. Parses higher-level info out of dpkt.http.Request
    Members:
    * query: Query string name-value pairs. {string: [string]}
    * host: hostname of server.
    * fullurl: Full URL, with all components.
    * url: Full URL, but without fragments. (that's what HAR wants)
    '''

    def __init__(self, tcpdir, pointer):
        http.Message.__init__(self, tcpdir, pointer, dpkt_http.Request)
        if 'content-type' in self.msg.headers:
            self.mediaType = MediaType(self.msg.headers['content-type'])
        else:
            self.mediaType = MediaType('application/x-unknown-content-type')
        self.mimeType = self.mediaType.mimeType()
        # first guess at body size. handle_compression might
        # modify it, but this has to be before clear_body
        self.body_length = len(self.msg.body)
        self.compression_amount = None
        self.text = None
        # handle body stuff
        if settings.drop_bodies:
            self.clear_body()
        else:
            # uncompress body if necessary
            self.handle_compression()
            # try to get out unicode
            self.handle_text()

        # get query string. its the URL after the first '?'
        uri = urlparse.urlparse(self.msg.uri)
        self.host = self.msg.headers['host'] if 'host' in self.msg.headers else ''
        fullurl = urlparse.ParseResult('http', self.host, uri.path, uri.params, uri.query, uri.fragment)
        self.fullurl = fullurl.geturl()
        self.url, frag = urlparse.urldefrag(self.fullurl)
        self.query = urlparse.parse_qs(uri.query, keep_blank_values=True)
