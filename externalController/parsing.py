import string
HOST = "http://www.geocities.com/"
# Replace with your own auth token or path to it. Be careful not to upload it.
AUTH = "YOUR TOKEN HERE"

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



