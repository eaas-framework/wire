import string
HOST = "http://www.geocities.com/"
AUTH = "YOU AUTH TOKEN"

def httpReqMan(data):
    """Function parsing and changing a given HTTP-request,
        returning the manipulated verison."""
    request = data
    request = string.replace(request, 'GET /', 'GET ' + HOST)
    request = string.replace(request, '\r\n\r\n',
                             '\r\nProxy-Authorization: ' + AUTH 
                             + '\r\n\r\n')
    print request
    return request



