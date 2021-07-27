def decode_base64(input_string=None, split_input=None, split_character=None, **kwargs):
    """
    Attempts to find and decode a base64 string. This will error out if the string is not valid.
    
    Args:
        input_string (CEF type: *): An input string or artifact path
        split_input: Decide to split the input
        split_character: Character to split by. Only applies if split_input is set to True. If blank, defaults to space. Use character name, e.g. 'space', 'colon', 'comma' or the actual character.
    
    Returns a JSON-serializable object that implements the configured data paths:
        decoded_b64.*.value: Base64 decoded string only
        original_string: Passthrough of the string that was entered as input_string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import base64
    import unicodedata

    # Helper function to determine if the string has any base64
    def isBase64(sb):
        try:
            if isinstance(sb, str):
                    # If there's any unicode here, an exception will be thrown and the function will return false
                    sb_bytes = bytes(sb, 'ascii')
            elif isinstance(sb, bytes):
                    sb_bytes = sb
            else:
                    raise ValueError("Argument must be string or bytes")
            return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        except Exception:
                return False
            
    # Helper function to decode base64
    def decode64(s):
        try:
            s_bytes = s.encode('ascii')
            data = base64.b64decode(s_bytes, validate=True)
            if data:
                return data.decode('ascii').replace('\x00','')
        except Exception as e:
            raise RuntimeError(f'Unable to decode string: {e}')
    
    # Check command variable
    if isinstance(split_input, str) and split_input.lower() in ['t', 'true', 'y', 'yes']:
        split_input = True
    elif isinstance(split_input, str) and split_input.lower() in ['f', 'false', 'n', 'no']:
        split_input = False
    
    if split_input:
        if isinstance(split_character, str):
            try:
                split_character = unicodedata.lookup(split_character)
            except Exception as e:
                phantom.debug(f"Treating '{split_character}' as literal")
        else:
            split_character = ' '
    
    outputs = {'decoded_string': None, 'decoded_b64': [], 'original_string': None}
    
    if input_string:
        if split_input:
            for value in input_string.split(split_character):      
                if isBase64(value):
                    decoded_value = decode64(value)
                    outputs['decoded_b64'].append({'value': decoded_value})
            if outputs['decoded_b64']:
                outputs['original_string'] = input_string
        else:
            if isBase64(input_string):
                decoded_value = decode64(input_string)
                if decoded_value:
                    outputs['decoded_b64'].append({'value': decoded_value})
                    outputs['original_string'] = input_string
            
                    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
