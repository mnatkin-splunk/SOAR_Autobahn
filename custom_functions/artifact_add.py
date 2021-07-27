def artifact_add(cef=None, severity=None, container_id=None, label=None, name=None, field_mapping=None, run_automation=None, **kwargs):
    """
    Add an artifact to a container
    
    Args:
        cef
        severity
        container_id
        label
        name
        field_mapping
        run_automation
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.artifact_id
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    # set run automation based on user_input
    if not run_automation or run_automation.lower() == 'false':
        run_automation = False
    elif run_automation.lower() == 'true':
        run_automation = True
    
    count = 1
    len_cef = len(cef)
    # iterate through all input cef
    for art_cef, f_map, art_name in zip(cef, field_mapping, name):
        
        if count < len_cef:
            # create new artifact w/o run automation
            success, message, artifact_id = phantom.add_artifact(
                container=container_id, raw_data={}, 
                cef_data=art_cef, 
                label=label,
                field_mapping=f_map,
                name=art_name, 
                severity=severity,
                run_automation=False)
            outputs.append({'artifact_id': artifact_id})

        elif count == len_cef:
            phantom.debug("Setting final artifact run_automation to {}".format(run_automation))
            # create new artifact w/ run automation
            success, message, artifact_id = phantom.add_artifact(
                container=container_id, raw_data={}, 
                cef_data=art_cef, 
                label=label,
                field_mapping=f_map,
                name=art_name, 
                severity=severity,
                run_automation=run_automation)
            outputs.append({'artifact_id': artifact_id})
            
        count += 1

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
