def parse_url_py3(url=None, **kwargs):
    """
    Args:
        url
    
    Returns a JSON-serializable object that implements the configured data paths:
        domain (CEF type: domain)
        path
        params
        scheme
        url (CEF type: url)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from urllib.parse import urlparse
    
    outputs = {}
    
    urlparts = urlparse(url)
    
    outputs = {
        'domain': urlparts.netloc,
        'path': urlparts.path,
        'params': urlparts.params,
        'scheme': urlparts.scheme,
        'url': url
    }
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
