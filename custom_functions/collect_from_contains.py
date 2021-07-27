def collect_from_contains(container=None, contains=None, tags=None, scope=None, **kwargs):
    """
    Returns artifact values that match any known cef data types on this Phantom instance
    
    Args:
        container (CEF type: phantom container id): Phantom container id or container object
        contains (CEF type: *): Individual cef types or a comma separated list: e.g.: hash,filehash,file_hash
        tags (CEF type: *): Individual tags or a comma separated list.
        scope: Select artifact scope to retrieve. Accepted values: all or new. Defaults to new if left blank.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.artifact_value (CEF type: *): Unpacked artifact values
        *.artifact_id (CEF type: phantom artifact id): Phantom artifact id
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import traceback
    
    outputs = []
    contains_list = []
    tags_list = []
    value_list = []
    
    # Check for valid container type
    if isinstance(container, int):
        container = phantom.get_container(container)
    elif not isinstance(container, dict):
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # Split contains if it contains commas or use as-is
    if contains and "," in contains:
        contains_list = contains.split(",")
        contains_list = [item.strip() for item in contains_list]
    else:
        contains_list.append(contains)
    
    # Split tags if it contains commas or use as-is
    if tags and "," in tags:
        tags_list = tags.split(",")
        tags_list = [item.strip() for item in tags_list]
    else:
        tags_list.append(tags)
        
    # Try phantom.collect_from_contains()
    for item in contains_list:
        try:
            values = phantom.collect_from_contains(container=container, contains=[item], tags=tags, scope=scope)
            for v in values:
                if v:
                    value_list.append(v)
    
        except TypeError as type_error:
            phantom.error(f"Encounted TypeError: '{type_error}' when retrieving collect for item: '{item}'")
            continue

    # Grab all artifacts to preserve mapping later
    artifact_url = phantom.build_phantom_rest_url('container', container['id'], 'artifacts')
    artifact_json = phantom.requests.get(uri=artifact_url, verify=False).json()
    artifact_data = []
    if artifact_json.get('count') and artifact_json.get('count') > 0:
        for data in artifact_json.get('data'):
            artifact_data.append(data)

    # Output deduped artifact values
    if value_list:
        # Iterate and dedup value_list
        for item in list(set(value_list)):
            if item: 
                for data in artifact_data:
                    for k,v in data['cef'].items():
                        if v == item:
                            outputs.append({'artifact_value': v, 'artifact_id': data['id']}) 
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
