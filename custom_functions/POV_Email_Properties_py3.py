def POV_Email_Properties_py3(container_id=None, **kwargs):
    """
    Gets Email properties, and renames artifacts ready for downstream playbooks.
    
    Args:
        container_id (CEF type: phantom container id)
    
    Returns a JSON-serializable object that implements the configured data paths:
        outputs (CEF type: *)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    email_properties = {
       'isMSFTEmail': None,
       'hasMultipleEmailArtifacts': None, 
       'hasMSGFileAttached': None, 
       'isEMLForwarded': None, 
       'isMSGForwarded': None,
       'vaultHasPossibleExecutable': None,
       'attachmentIsCompressed': None,
       'vaultIdForExecutable': None,
       'forwarded_artifact_id': None,
       'phish_artifact_id': None,
       'hasRanPreviously': None,
       'vaultArtifactWithExecutable': None,
       'phishing_reporter': None
    }
    
    
    vaultIds = []
    vaultFileName = []
    executableVaultArtifact = []
    fromEmailAddress = None
    
    # Write your custom code here...
    import re
    phantom.debug(container_id)
    
    try:
        artifact_url = phantom.build_phantom_rest_url('artifact')
        phantom.debug('artifact url : {}'.format(artifact_url))
        artifact_name = '\"Email Artifact\"'
        params = {
            '_filter_container': container_id,
            '_filter_name': artifact_name
            
        }
        response = phantom.requests.get(artifact_url, params=params,verify=False)
        r = response.json()
        phantom.debug('[+] getting URL: {0} returned: {1}'.format(artifact_url,r))
        artifacts = r['data']
        phantom.debug('Got Artifacts: {}'.format(artifacts))
        
    except Exception as e:
        phantom.error('Unable to get artifacts for container id: {0} Error: {1}'.format(container_id, e))
        
    
    # Count the number of email artifacts retrieved.
    try:
        if r['count'] == 0:
            phantom.debug('Get Artifacts Retrieved No "Email Artifact" Records - Likely Ran previously - Rename back if you want to rerun.')
            email_properties['hasRanPreviously'] = True
    except:
        pass
    
    try:
        if r['count'] > 1:
            phantom.debug('got some : {}'.format(r['count']))
            email_properties['hasMultipleEmailArtifacts'] = True
        
    except Exception as e:
        phantom.error('failed counting artifacts: {}'.format(e))
        
        
        
    # ---- Get Vault And look for .msg files, and Dangerous Executables. 
    success, message, info = phantom.vault_info(container_id=container_id)
    if success:
        for vault_item in info:
            
            if re.search("\.doc|\.docx|\.exe|\.pdf|\.xls|\.zip|\.rar", vault_item['name']):
                email_properties['vaultHasPossibleExecutable'] = True
                vaultIds.append(vault_item['vault_id'])
                vaultFileName.append(vault_item['name'])
                phantom.debug('Found a potentially executable file: {}'.format(vault_item['name']))
            
            if re.search("\.msg$", vault_item['name']):
                email_properties['hasMSGFileAttached'] = True
                email_properties['isMSGForwarded'] = True
                phantom.debug('Setting hasMSGFileAttached')
                phantom.debug('Setting isMSGForwarded')
    
    else:
        phantom.error('ERROR Fetching Vault Items: {}'.format(message))
    
    email_properties['vaultIdForExecutable'] = vaultIds
    
    
    # If we discovered potentially executable files - Look for the artifact and rename them
    try:
        vault_artifact_url = phantom.build_phantom_rest_url('artifact')
        phantom.debug('artifact url : {}'.format(vault_artifact_url))
        artifact_name = '\"Vault Artifact\"'
        params = {
            '_filter_container': container_id,
            '_filter_name': artifact_name
            
        }
        response = phantom.requests.get(vault_artifact_url, params=params,verify=False)
        r = response.json()
        vault_artifacts = r['data']
        phantom.debug('Got Vault Artifacts: {}'.format(vault_artifacts))
        
    except Exception as e:
        phantom.error('Unable to get Vault artifacts for container id: {0} Error: {1}'.format(container_id, e))
    
    for vault_artifact in vault_artifacts:
        phantom.debug('Vault Artifact: {}'.format(vault_artifact))
        for file_name in vaultFileName:
            if file_name == vault_artifact['cef']['fileName']:
                phantom.debug('Found Match: Artifact id is: {}'.format(vault_artifact['id']))
                executableVaultArtifact.append(vault_artifact['id'])
    
    email_properties['vaultArtifactWithExecutable'] = executableVaultArtifact
    
    # ---- END OF VAULT SECTION ---- #
        
    # ---- Work through Artifact(s) collected ---- #
    
    for artifact in artifacts:
        phantom.debug('working on artifact: {}'.format(artifact['id']))
        
        # Determined if the enterprise mail system is likely Exchange
        try: 
            artifact['cef']['emailHeaders']['X-MS-Exchange-Organization-AuthAs']
            isExchange = True
        except KeyError: 
            isExchange = None
            
        if isExchange == True or "Microsoft Exchange" in artifact['description']:
            phantom.debug('Setting isMSFTEmail flag')
            email_properties['isMSFTEmail'] = True
        
            
        # If No MSG file found, and MSFT Tech, and more than 1 Email Artifact already, likely
        # this is a forwarded .eml message already parsed.
        try:
            if email_properties['hasMultipleEmailArtifacts'] and email_properties['isMSFTEmail'] and not email_properties['hasMSGFileAttached'] :
                email_properties['isEMLForwarded'] = True
                phantom.debug('Setting isEMLForwarded flag')
                
                # Identify which artifact we have (forwarding wrapper, or the phish artifact)
                try:
                    pos = re.search(r"@(.*)\>", artifact['cef']['fromEmail'] )
                    fromEmailDomain = pos.group(1)
                    pos = re.search(r"(\<)(.*)(\>)", artifact['cef']['fromEmail'] )
                    fromEmailAddress = pos.group(2)
                    phantom.debug('fromEmailAddress: {}'.format(fromEmailAddress))
                except:
                    phantom.error('ERROR locating the from domain from: {}'.format(artifact['cef']['fromEmail']))
                
                try:
                    pos = re.search(r"@(.*)\>", artifact['cef']['toEmail'] )
                    toEmailDomain = pos.group(1)
                except:
                    phantom.error('ERROR locating the to domain from: {}'.format(artifact['cef']['toEmail']))
                

                if  fromEmailDomain == toEmailDomain:
                    email_properties['forwarded_artifact_id'] = artifact['id']
                    phantom.debug('Setting forward artifact to id: {} for EML file'.format(artifact['id']))
                    email_properties['phishing_reporter'] = fromEmailAddress
                    
                if  fromEmailDomain != toEmailDomain:
                    email_properties['phish_artifact_id'] = artifact['id']
                    phantom.debug('Setting phish artifact to id: {} for EML file'.format(artifact['id']))
                
        except Exception as e:
            phantom.debug('Error(1): {}'.format(e))
            
            continue
            
        # If MSFT Email and MSG file has been attached Identify which artifact we have (forwarding wrapper of the phish artifact)
        if email_properties['isMSFTEmail'] and email_properties['hasMSGFileAttached']:
            
            try:
                pos = re.search(r"@(.*)\>", artifact['cef']['fromEmail'] )
                fromEmailDomain = pos.group(1)
                pos = re.search(r"(\<)(.*)(\>)", artifact['cef']['fromEmail'] )
                phantom.debug('pos: {}'.format(pos))
                fromEmailAddress = pos.group(2)
                phantom.debug('fromEmailAddress: {}'.format(fromEmailAddress))
            except:
                phantom.error('ERROR locating the from domain from: {} : {}'.format(artifact['cef']['fromEmail'], pos.group(2)))
                
            try:
                pos = re.search(r"@(.*)\>", artifact['cef']['toEmail'] )
                toEmailDomain = pos.group(1)
            except:
                phantom.error('ERROR locating the to domain from: {}'.format(artifact['cef']['toEmail']))
            
            if not artifact['cef']['bodyText'] and \
                fromEmailDomain != toEmailDomain:
                email_properties['phish_artifact_id'] = artifact['id']
                phantom.debug('Setting phish artifact to id: {} for MSG file'.format(artifact['id']))
                    
            if artifact['cef']['bodyText'] and \
                fromEmailDomain == toEmailDomain:
                email_properties['forwarded_artifact_id'] = artifact['id']
                phantom.debug('Setting forwarded artifact to id: {} for MSG file'.format(artifact['id']))
                email_properties['phishing_reporter'] = fromEmailAddress
                           
        
    
    # If only a single Email Artifact and the fromDomain and toDomain are the same, we need to try and discover the original sender
    # TO DO - We have the Domain Artifact to lookup - maybe don't need the sending user at all. Apart from Intel Development.
    # Which can be added manually be an analyst if appropriate.
    
    # ----- END OF ARTIFACT DOSCOVERY ------- 
    if email_properties['hasRanPreviously'] == None:
        if not email_properties['hasMultipleEmailArtifacts'] and not email_properties['hasMSGFileAttached']:
            phantom.debug('Discovered a single Email Artifact - Should be parsed OK.')
            email_properties['phish_artifact_id'] = artifacts[0]['id']
            pos = re.search(r"(\<)(.*)(\>)", artifact['cef']['fromEmail'] )
            email_properties['phishing_reporter'] = pos.group(2)
            
    
    
    phantom.debug('Determined Phish Artifact as: {0} and Forwarded Artifact as{1}'.format(email_properties['phish_artifact_id'],email_properties['forwarded_artifact_id']))   
        
    
    phantom.debug('Email Properties dict: {}'.format(email_properties))
    
    outputs = email_properties.copy()
    phantom.debug('returning: {}'.format(outputs))
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
