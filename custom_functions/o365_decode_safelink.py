def o365_decode_safelink(input_url=None, **kwargs):
    """
    This function takes safelinks URLs and decodes them in order to be usable downstream in playbooks .
    
    Args:
        input_url (CEF type: url)
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.decoded_url (CEF type: url)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import urllib
    
    # Create an outputs list to store decoded urls
    outputs = []
    
    # Loop through the input data, decode the urls, and add it to the output
    for item in input_url:
        phantom.debug('Processing loop item : ' + str(item))
        linkAfterQuestionMark = item.split('?')[1]
        linkParams = linkAfterQuestionMark.split('&')
        
        for param in linkParams:
            key, value = param.split('=')[0], param.split('=')[1]
            if key.lower() == 'url':
                target_url = value
                parsed = urllib.parse.unquote(value)
        
        # Add decoded URL to the data output
        this_output = {}
        this_output['decoded_url'] = parsed
        outputs.append(this_output)
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
