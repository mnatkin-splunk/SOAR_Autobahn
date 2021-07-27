def artifact_update(artifact_id=None, input_json=None, overwrite=None, **kwargs):
    """
    Update artifact with a valid json dictionary. See Phantom Artifact REST API for valid dictionary.
    
    
    Args:
        artifact_id (CEF type: phantom artifact id): A phantom artifact ID to update
        input_json: JSON dictionary to update artifact
        overwrite: Whether or not to overwrite existing fields with  supplied input json. Defaults to False
    
    Returns a JSON-serializable object that implements the configured data paths:
        id (CEF type: phantom artifact id): ID of the artifact that was updated
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    # Helper function to update fields
    def field_updater(data, update_data, overwrite):
        if type(update_data) == list:
            if not(overwrite):
                return(list(set((data or []) + update_data)))
            else:
                return(update_data)
        elif type(update_data) == dict:
            for keya in update_data.keys():
                data[keya] = field_updater(data.get(keya, {}), update_data[keya], overwrite)
        else:
            if (overwrite and data) or not(data):
                return update_data  
            
        return data
            
    if isinstance(overwrite, str) and overwrite.lower() in ['t', 'true', 'y', 'yes']:
        overwrite = True
    else:
        overwrite = False
        
    outputs = {}
    phantom.debug(input_json)
    try:
        data = json.loads(input_json)
    except Exception as e:
        raise TypeError(f"Input_json is invalid: '{e}'")
        
    artifact_url = phantom.build_phantom_rest_url('artifact', artifact_id)
    
    response = phantom.requests.get(artifact_url, verify=False)
    if response.status_code != 200:
        raise RuntimeError(f"Unable to find artifact id: {artifact_id}. Response '{response.json}'")
        
    artifact_data = response.json()
    update_data = {}
    for key in data.keys():
        update_data[key] = field_updater(artifact_data.get(key, {}), data[key], overwrite)
        
    post_response = phantom.requests.post(artifact_url, data=json.dumps(update_data), verify=False)
    
    if post_response.status_code != 200:
        raise RuntimeError(f"Unable to save artifact data. Response: '{post_response.text}'")
        
    else:
        outputs['id'] = artifact_id

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
