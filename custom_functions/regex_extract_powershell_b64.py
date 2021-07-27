def regex_extract_powershell_b64_py3(input_string=None, artifact_id=None, **kwargs):
    """
    Detects -enc flag and extracts base64. Based on Unit42 research.
    
    Args:
        input_string (CEF type: *): A powershell cmdline that may contain encoding flag
        artifact_id (CEF type: phantom artifact id): Phantom Artifact ID
    
    Returns a JSON-serializable object that implements the configured data paths:
        extracted_string (CEF type: *): Base 64 extracted from input_string. Empty if extraction failed.
        artifact_id (CEF type: phantom artifact id): Phantom Artifact ID
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    from base64 import b64decode
    outputs = {}
    pattern = '\-[eE^]{1,2}[NnCcOoDdEeMmAa^]+\s+([^\s]+)'
    nested_pattern = "frombase64string\('(\S+)'\)"
    if input_string:
        if re.search(pattern,str(input_string)):
            captured_string = re.search(pattern,str(input_string)).group(1)
            outputs['extracted_string'] = captured_string
            outputs['artifact_id'] = artifact_id
            phantom.debug("Found encoded command string")
        elif re.search(nested_pattern, str(input_string), re.IGNORECASE):
            captured_string = re.search(nested_pattern, str(input_string), re.IGNORECASE).group(1)
            outputs['extracted_string'] = captured_string
            outputs['artifact_id'] = artifact_id
            phantom.debug("Found frombase64 command" + str(captured_string))
        else:
            phantom.debug("No base64 encoding detected")
            
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
