def json_serializer_py3(input_key=None, input_value=None, **kwargs):
    """
    Takes a key and a value and serializes it into a json dictionary to be used wherever a pre-formatted json required
    
    Args:
        input_key (CEF type: *): To be used as json key
        input_value (CEF type: *): To be used as a json value
    
    Returns a JSON-serializable object that implements the configured data paths:
        json (CEF type: *): json key:value
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    outputs['json'] = json.dumps({input_key: input_value})
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
