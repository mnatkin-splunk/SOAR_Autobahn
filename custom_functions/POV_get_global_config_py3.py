def POV_get_global_config_py3(return_keys=None, **kwargs):
    """
    Takes a comma separated list of keys to retrieve from globalconfig custom list.
    
    Args:
        return_keys (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        global_item (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    lookup_keys = return_keys.split(",")
    
    if len(lookup_keys) == 0:
        phantom.error('[+] No keys passed for lookup')
        return

    try:
        success, message, custom_keys = phantom.get_list(list_name='globalconfig')
        phantom.debug(custom_keys)
    except:
        phantom.error('[+] Failed to get custom list')
        return
    
    
    global_item = []
    for item in custom_keys:
        #phantom.debug('looking at: value: {0}'.format(item[0]))
        for req_key in lookup_keys:
            #phantom.debug('req_key: {}'.format(req_key))
            if req_key == item[0]:
                global_item.append({req_key: item[1]})
                phantom.debug('FOUND A MATCH: {}'.format(item[1]))
        
    
    outputs = global_item
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
