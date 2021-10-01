def whitelist_domain(input=None, **kwargs):
    """
    This function takes a list of strings (i.e. "https://www.splunk.com") and filters out any domains contained in a whitelist (i.e. "splunk.com"). It outputs a list of items that were not matched by the whitelist. Note that the whitelist is maintained in the function itself. Edit this function to change the whitelist.
    
    Args:
        input (CEF type: *): Select a field that has domains or urls that will be compared to a whitelist.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.whitelisted_result (CEF type: *): Output of domains or urls that were not in the whitelist.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    # Edit this list to contain all domains you want filtered out (whitelisted)
    whitelist = []
    whitelist.append('www.instagram.com')
    whitelist.append('www.youtube.com')
    whitelist.append('www.facebook.com')
    whitelist.append('www.twitter.com')
    whitelist.append('www.linkedin.com')
    
    # 
    phantom.debug('Removing the following domains from the data: ' + str(whitelist))
    
    # Loop through the items in the input list.
    for i in input:
        match = 'false'
        
        # Loop through the whitelist and find matches
        for w in whitelist:
            if str(i.find(w)) != '-1':
                match = 'true' 
        
        # Add to the output if no match was found
        if match == 'false':
            this_output = {}
            this_output['whitelisted_result'] = i
            outputs.append(this_output)
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
