def update_artifact_py3(artifact_id=None, data=None, overwrite=None, **kwargs):
    """
    Update artifact with a valid json dictionary. See Phantom Artifact REST API for valid dictionary.
    
    Args:
        artifact_id (CEF type: *): ID of artifact to update
        data (CEF type: *): JSON formatted data. See artifact REST api
        overwrite (CEF type: *): Optional: Leave blank for False
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    def field_updater(data, update_data, overwrite):
        if type(update_data) == list:
            if not(overwrite):
                return(list(set((data or []) + update_data)))
            else:
                return(update_data)
        elif type(update_data) == dict:
            for keya in list(update_data.keys()):
                data[keya] = field_updater(data.get(keya, {}), update_data[keya], overwrite)
        else:
            if (overwrite and data) or not(data):
                return update_data  
            
        return data
    
    outputs = {}
    try:
        data = json.loads(data)
    except Exception as err:
        return phantom.error('Unable to parse "data" field: {}'.format(err))
    
    if not overwrite:
        overwrite = False
        
    artifact_url = phantom.build_phantom_rest_url('artifact/{}'.format(artifact_id))
    
    response = phantom.requests.get(artifact_url, verify=False)
    if response.status_code != 200:
        return phantom.error('Unable to find artifact id: {}. Response: {}'.format(artifact_id, response.text))
    
    artifact_data = response.json()
    update_data = {}
    for key in list(data.keys()):
        update_data[key] = field_updater(artifact_data.get(key, {}), data[key], overwrite)
        
    post_response = phantom.requests.post(artifact_url, data=json.dumps(update_data), verify=False)
    
    if post_response.status_code != 200:
        return phantom.error('Unable to save artifact data: {}'.format(post_response.text))

    phantom.debug('Successfully updated artifact ID: {}'.format(artifact_id))

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
