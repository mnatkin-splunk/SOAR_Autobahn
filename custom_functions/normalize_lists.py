def normalize_lists_py3(input_item=None, object_type=None, **kwargs):
    """
    Takes in an object that may be a single element or a list and normalizes the output. Data can be accessed by items.*.<object_type>. Object_type defaults to 'object_type'
    
    Args:
        input_item
        object_type
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.item
        *.object_type
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    if input_item and type(input_item) == list and object_type:
        phantom.debug('"{}" is a list, looping through'.format(input_item))
        for item in input_item:
            outputs.append({'item': item, 'object_type': object_type})
    elif input_item and object_type:
        phantom.debug('"{}" is not a list, adding item as-is'.format(input_item))
        outputs.append({'item': input_item, 'object_type': object_type})
    
    phantom.debug('Input: "{}" - Output: "{}"'.format(input_item,outputs))
    
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
