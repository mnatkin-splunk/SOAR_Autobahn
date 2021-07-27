def POV_artifact_count_py3(request_path=None, **kwargs):
    """
    Returns the number of artifacts on the datapath
    
    Args:
        request_path (CEF type: *): Enter the datapath you want to count the number of entries for
    
    Returns a JSON-serializable object that implements the configured data paths:
        num_artifacts (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    elems = len(request_path)
    outputs = {
        'num_artifacts' : elems
    }
    phantom.debug('datapath {0} has {1} elements'.format(request_path, elems))
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
