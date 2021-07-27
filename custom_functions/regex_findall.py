def regex_findall_py3(input_string=None, input_pattern=None, artifact_id=None, **kwargs):
    """
    Custom function implementation of re.find_all. Takes an input_string and a regex_pattern and returns matches (up to 8).
    
    Args:
        input_string (CEF type: *): A string to run regex against
        input_pattern (CEF type: *): Regex pattern goes here
        artifact_id
    
    Returns a JSON-serializable object that implements the configured data paths:
        all (CEF type: *): Entire result of re.findall
        group1 (CEF type: *)
        group2 (CEF type: *)
        group3 (CEF type: *)
        group4 (CEF type: *)
        group5 (CEF type: *)
        group6 (CEF type: *)
        group7 (CEF type: *)
        group8 (CEF type: *)
        artifact_id (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = {}
    
    pattern = '{}'.format(input_pattern)
    
    result = re.findall(pattern, input_string)
    outputs['all'] = result
    outputs['artifact_id'] = artifact_id
    if input_string:
        
        result = re.findall(pattern, input_string)
        incrementer = 1
        outputs['all'] = result
        
        if len(result) > 9:
            phantom.debug('Number of capture groups greater than allowable output size of 8. Returning first 8')
            for capture_group in result[:8]:
                if type(capture_group) == tuple:
                    for item in capture_group:
                        outputs['group' + str(incrementer)] = item
                        incrementer += 1
                else:
                    outputs['group' + str(incrementer)] = capture_group
                    incrementer +=1
                    
        elif result:
            for capture_group in result:
                if type(capture_group) == tuple:
                    for item in capture_group:
                        outputs['group' + str(incrementer)] = item
                        incrementer += 1
                else:
                    outputs['group' + str(incrementer)] = capture_group
                    incrementer += 1
                    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
