def CreateEventID(id_value=None, **kwargs):
    """
    Args:
        id_value (CEF type: phantom container id)
    
    Returns a JSON-serializable object that implements the configured data paths:
        eventLink (CEF type: splunk notable event id)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    baseUrl = phantom.get_base_url()
    CreateEventUrl__eventLink = baseUrl + "/mission/" + str(int(id_value))
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
