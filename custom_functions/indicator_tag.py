def indicator_tag(indicator=None, tags=None, **kwargs):
    """
    Tag an indicator by list
    
    Args:
        indicator (CEF type: *): An indicator value to tag
        tags (CEF type: *): Comma separated list of tags
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    url = phantom.build_phantom_rest_url('indicator')
    response = phantom.requests.get(url + f'?_filter_value="{indicator}"', verify=False).json()
    
    
    if response['count'] > 0:
        phantom.debug(f'{response["count"]} indicator(s) returned. Adding tags - "{tags}"')
        for indicator_record in response['data']:
            data = {"tags": tags.split(',')}
            phantom.debug(phantom.requests.post(url + f'/{indicator_record["id"]}', json=data, verify=False).json())
        
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
