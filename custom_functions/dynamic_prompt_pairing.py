def dynamic_prompt_pairing_py3(input_json=None, response=None, **kwargs):
    """
    Args:
        input_json (CEF type: *)
        response (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        type (CEF type: *): item
        value (CEF type: *): url, domain, sender, etc.
        response (CEF type: *): Yes / No
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    outputs['type'] = list(input_json.keys())[0]
    outputs['value'] = list(input_json.values())[0]
    outputs['response'] = response
    # Return a JSON-serializable object
    phantom.debug(outputs)
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs