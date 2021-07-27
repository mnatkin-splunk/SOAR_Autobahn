def decode_base64_py3(input_string=None, artifact_id=None, **kwargs):
    """
    Decodes provided base64 string
    
    Args:
        input_string (CEF type: *): Base64 encoded text
        artifact_id (CEF type: phantom artifact id): Phantom Artifact ID
    
    Returns a JSON-serializable object that implements the configured data paths:
        decoded_string (CEF type: *): Base64 decoded string
        artifact_id (CEF type: phantom artifact id): Phantom Artifact ID
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    from base64 import b64decode
    outputs = {}

    if input_string:
        if input_string.endswith('=='):
            phantom.debug('padding exists')
        elif input_string.endswith('='):
            phantom.debug('padding string with "="')
            input_string += '='
        else:
            phantom.debug('padding string with "=="')
            input_string += '=='
            
        try:    
            decoded_string = b64decode(input_string).replace('\x00','')
            outputs['decoded_string'] = decoded_string
            outputs['artifact_id'] = artifact_id
            
        except Exception as e:
            phantom.error('Uable to decode b64 string - {}'.format(e))
            
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
