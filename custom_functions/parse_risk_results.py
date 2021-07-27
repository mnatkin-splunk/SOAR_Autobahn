def parse_risk_results(search_json=None, **kwargs):
    """
    Parse risk results from a Splunk search Action Results "data" key. Adjust the key:value dictionary at the beginning to affect cim > cef translation. For IP addresses in a hostname field, this custom function will attempt to recognize and rename to a CEF field that contains IP addresses. The custom function also maps a threat_object_type to the "field_mapping" field of a Phantom artifact so that the "threat_object" has the correct contains type. Finally, it will do normalization on the _time field, add risk_message to artifact description, add splunk source to artifact name, and add any mitre_techniques to artifact_tags.
    
    Args:
        search_json: A JSON formatted dictionary. This is expected to come from the .data key of a Splunk search result.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.artifact.cef: A CEF dictionary
        *.artifact.tags: A deduped list of artifact tags
        *.artifact.name: The name of the artifact
        *.artifact.field_mapping: The underlying data types for the artifact's important fields
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from dateutil.parser import parse
    from django.utils.dateparse import parse_datetime
    import re
    
    outputs = []
    # Helper recursive function to flatten nested lists
    def flatten(input_list):
        if not input_list:
            return input_list
        if isinstance(input_list[0], list):
            return flatten(input_list[0]) + flatten(input_list[1:])
        return input_list[:1] + flatten(input_list[1:])
    
    # Declare dictionary for cim to cef translation
    cim_cef = {
        "action": "act", 
        "action_name": "act", 
        "app": "app", 
        "bytes_in": "bytesIn", 
        "bytes_out": "bytesOut", 
        "category": "cat", 
        "dest": "destinationAddress", 
        "dest_ip": "destinationAddress", 
        "dest_mac": "destinationMacAddress", 
        "dest_nt_domain": "destinationNtDomain", 
        "dest_port": "destinationPort", 
        "dest_translated_ip": "destinationTranslatedAddress", 
        "dest_translated_port": "destinationTranslatedPort", 
        "direction": "deviceDirection",
        "dns": "destinationDnsDomain", 
        "dvc": "dvc", 
        "dvc_ip": "deviceAddress", 
        "dvc_mac": "deviceMacAddress", 
        "file_create_time": "fileCreateTime", 
        "file_hash": "fileHash", 
        "file_modify_time": "fileModificationTime", 
        "file_name": "fileName", 
        "file_path": "filePath", 
        "file_size": "fileSize", 
        "message": "message", 
        "protocol": "transportProtocol", 
        "request_payload": "request", 
        "request_payload_type": "requestMethod", 
        "src": "sourceAddress", 
        "src_dns": "sourceDnsDomain", 
        "src_ip": "sourceAddress", 
        "src_mac": "sourceMacAddress", 
        "src_nt_domain": "sourceNtDomain", 
        "src_port": "sourcePort", 
        "src_translated_ip": "sourceTranslatedAddress", 
        "src_translated_port": "sourceTranslatedPort", 
        "src_user": "sourceUserId", 
        "transport": "transportProtocol", 
        "url": "requestURL", 
        "user": "destinationUserName", 
        "user_id": "destinationUserId", 
    }
    
    
    # Iterate through Splunk search results
    for artifact_json in search_json[0]:
        field_mapping = {}
        
        for k,v in artifact_json.items():
            tags = []
            # Swap CIM for CEF values
            if k.lower() in cim_cef.keys():
                if k.lower() == 'dest':
                    # if 'dest' matches an IP, use 'dest', otherwise use 'destinationHostName'
                    if re.match('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', k):
                        artifact_json[cim_cef[k]] = artifact_json.pop(k)
                    else:
                        artifact_json['destinationHostName'] = artifact_json.pop(k)
                elif k.lower() == 'src':
                    # if 'src' matches an IP, use 'src', otherwise use 'sourceHostName'
                    if re.match('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', k):
                        artifact_json[cim_cef[k]] = artifact_json.pop(k)
                    else:
                        artifact_json['sourceHostName'] = artifact_json.pop(k)
                else:
                    artifact_json[cim_cef[k.lower()]] = artifact_json.pop(k)
                    
        for k,v in artifact_json.items():
            if type(v) == list:
                artifact_json[k] = ", ".join(flatten(v))
                
        # Swap risk_message for description
        if 'risk_message' in artifact_json.keys():
            artifact_json['description'] = artifact_json.pop('risk_message')

        # Make _time easier to read
        if '_time' in artifact_json.keys():
            timestring = parse(artifact_json['_time'])
            artifact_json['_time'] = "{} {}".format(timestring.date(), timestring.time())

        # Add threat_object_type to threat_object field_mapping
        if 'threat_object' in artifact_json.keys() and 'threat_object_type' in artifact_json.keys():
            field_mapping['threat_object'] = [artifact_json['threat_object_type']]                  

        # Set the underlying data type in field mapping based on the risk_object_type     
        if 'risk_object' in artifact_json.keys() and 'risk_object_type' in artifact_json.keys():
            if 'user' in artifact_json['risk_object_type']:
                field_mapping['risk_object'] = ["user name"]
            elif artifact_json['risk_object_type'] == 'system':
                field_mapping['risk_object'] = ["host name", "hostname"]
            else:
                field_mapping['risk_object'] = artifact_json['risk_object_type']
            
        # Extract tags
        if 'rule_attack_tactic_technique' in artifact_json.keys():
            for match in re.findall('(^|\|)(\w+)\s+',artifact_json['rule_attack_tactic_technique']):
                tags.append(match[1])
            tags=list(set(tags))

        # Final setp is to build the output. This is reliant on the source field existing which should be present in all Splunk search results
        if 'source' in artifact_json.keys():
            name = artifact_json.pop('source')
            outputs.append({'artifact': {'cef': artifact_json, 'tags': tags, 'name': name, 'field_mapping': field_mapping}})

    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
