def get_run_data(key=None, flatten_lists=None, output_as_json=None, **kwargs):
    """
    Takes a key name and splits the output for easier access for actions downstream
    
    Args:
        key (CEF type: *): A text string that represents the name of the key saved for a save_run_data() call
        flatten_lists: Flatten nested lists 
            i.e: [ "list 1", ["nested list 1"] , "list 2" ]
        output_as_json: Reconstruct data as a valid json path output. If set to False, data will be sent straight to output without parsing.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.output: Start of output. If data contains valid JSON structures and output_as_json is set to True, access output keys as normal action results,
            i.e "*.output.my_key1"
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    # Helper recursive function to flatten nested lists
    def flatten(input_list):
        if not input_list:
            return input_list
        if isinstance(input_list[0], list):
            return flatten(input_list[0]) + flatten(input_list[1:])
        return input_list[:1] + flatten(input_list[1:])
    
    # Check to see if user selected flatten_list
    if isinstance(flatten_lists, str) and flatten_lists.lower() in ['y', 'yes', 't', 'true']:
        flatten_lists = True
    elif isinstance(flatten_lists, str) and flatten_lists.lower() in ['n', 'no', 'f', 'false']:
        flatten_lists = False
    elif not flatten_lists:
        flatten_lists = False
    
    # Check to see if output as json is checked
    if isinstance(output_as_json, str) and output_as_json.lower() in ['y', 'yes', 't', 'true']:
        output_as_json = True
    elif isinstance(output_as_json, str) and output_as_json.lower() in ['n', 'no', 'f', 'false']:
        output_as_json = False
    elif not flatten_lists:
        output_as_json = False
    
    
    fetched_data = phantom.get_run_data(key=key)
    if fetched_data:
        if output_as_json:
            # Try to load data as valid Json
            try:
                data_as_json = json.loads(fetched_data)
                if isinstance(data_as_json, str):
                    outputs.append({'output': data_as_json})
                elif isinstance(data_as_json, dict):
                    for k,v in data_as_json.items():
                        outputs.append({'output': {k: v}})
                elif isinstance(data_as_json, list):
                    if flatten_lists:
                        data_as_json = flatten(data_as_json)
                    for item in data_as_json:
                        outputs.append({'output': item})
            except Exception as e:
                # If not valid json or some error, just pass the fetched_data straight to output
                phantom.debug(f"Passing key straight to output due to exception: '{e}'")
                outputs.append({'output': fetched_data})
        else:
            outputs.append({'output': fetched_data})
    else:
        raise RuntimeError(f"No data for key: '{key}'")
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
