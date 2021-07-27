def add_artifact_with_tags_py3(cef=None, tags=None, severity=None, container_id=None, label=None, name=None, run_automation=None, field_mapping=None, **kwargs):
    """
    Adds an artifact and updates that artifact with provided tags
    
    Args:
        cef (CEF type: *)
        tags (CEF type: *)
        severity (CEF type: *)
        container_id (CEF type: phantom container id)
        label (CEF type: *)
        name (CEF type: *)
        run_automation (CEF type: *): Defaults to False
        field_mapping (CEF type: *): valid field_mapping json
    
    Returns a JSON-serializable object that implements the configured data paths:
        id
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    if not run_automation or run_automation.lower() == 'false':
        run_automation = False
    elif run_automation.lower() == 'true':
        run_automation = True
    
    try:
        phantom.debug("CEF passed in: " + cef)
        cef = json.loads(cef)
    except:
        phantom.debug("Was not able to load JSON from string, so just passing: ")
        # cef = json.dumps(cef)
        phantom.debug(cef)
        
    try:
        phantom.debug("Field Mapping passed in: " + field_mapping)
        field_mapping = json.loads(field_mapping)
    except:
        phantom.debug("Unable to laod JSON from field mapping, so just passing: ")
        phantom.debug(field_mapping)

    success, message, artifact_id = phantom.add_artifact(
            container=container_id, 
            raw_data={}, 
            cef_data=cef, 
            label=label,
            field_mapping=field_mapping,
            name=name, 
            severity=severity,
            run_automation=run_automation)
    
    artifact_url = phantom.build_phantom_rest_url('artifact', artifact_id)
    data = {'tags': tags}
    phantom.requests.post(artifact_url, data=json.dumps(data), verify=False)
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
