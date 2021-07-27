def assign_workbook(container_id=None, **kwargs):
    """
    This custom function assigns the workbook based on the container tag presented in order of precedence. 
    
    Args:
        container_id: Add the container id to add workbook to.
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    """ This section assigns the workbook based on the tags presented in the container.  The customer and consultant must defined these beforehand.
        Recommended templates are:
            Enrichment investigation = enrich = 65 (add url for listing config)
            Command and Control investigation = network = 81 (add url for listing config)
            Execution investigation = host = 30 (add url for listing config)
    """
    # Declare the assigment of workbooks to tag
    host = 30
    network = 81
    enrich = 65
    
    # Display tags for debugging
    success, message, tags = phantom.get_tags(container=container_id, trace=False)
    phantom.debug("Found the following container tags: {}".format(tags))
    
    if "host" in tags:
        phantom.debug("Host tag was presented, we will add the Identification - Execution workbook - ID:{}".format(host))
        success, message = phantom.add_workbook(container_id, host)
    elif "network" in tags:
        phantom.debug("Network tag was presented, we will add the Identification - Command and Control workbook - ID:{}".format(network))
        success, message = phantom.add_workbook(container_id, network)
    else:
        phantom.debug("By default, we will add the Identification - Indicator Enrichment workbook - ID:{}".format(enrich))
        success, message = phantom.add_workbook(container_id, enrich)    
    
    if success:
        phantom.debug('phantom.add_workbook succeeded. API message: {}'.format(message))
        # Call on_success callback
    else:
        phantom.error('phantom.add_workbook failed or was not called. API message: {}'.format(message))
        # Call on_fail callback
    outputs = message
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
