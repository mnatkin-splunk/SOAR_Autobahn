def POV_Add_Workbook_py3(container=None, **kwargs):
    """
    Reads the event label and auto assigns the correct workbook to the event.
    
    Args:
        container (CEF type: phantom container id): Input container id
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    def add_workbook(container=None, workbook_name=None):
        if container == None or workbook_name == None:
            phantom.error('POV_Auto_Add_Workbook - Failure')
            return
        
        params = {
                '_filter_name__icontains' : workbook_name
            }
            
        try:
            #Get Workbook_ID
            url = phantom.build_phantom_rest_url('workbook_template')
            response = phantom.requests.get(url, params=params, verify=False)
            r = response.json()
            workbook_id = r['data'][0]['id']
            
            #Add workbook
            success, message = phantom.add_workbook(container=container, workbook_id=workbook_id)
            if success:
                phantom.debug('phantom.add_workbook succeeded. API message: {}'.format(message))
            else:
                phantom.debug('phantom.add_workbook failed. API message: {}'.format(message))
        
        except:
            phantom.error('Error: Unable to add workbook')
            
        
        return
    
    # Get Container label and name
    try:
        cdata = phantom.get_container(container)
        container_label = cdata['label']
        container_name = cdata['name']
        
    except Exception as e:
        phantom.error('Unable to fetch container')
        return
        
    # Auto Assign Workbooks
    if container_label == "phishing_email":
        workbook_name = "'POV_Phishing_Investigation_Workbook'"
        add_workbook(container, workbook_name)
        phantom.debug('Phishing Email Workbook Added')
        
    if container_label == "aws_security_hub":
        workbook_name = "'POV_AWS_SecurityHub_Triage'"
        add_workbook(container, workbook_name)
        phantom.debug('Phishing Email Workbook Added')
        
    if container_label == "splunk_notable" and "ESCU - Detect Rare Process" in container_name:
        workbook_name = "'POV_Malware_Investigation_Workbook'"
        add_workbook(container, workbook_name)
        phantom.debug("Malware Investigation Workbook Added")
        
    if container_label == "splunk_notable" and "ESCU - Detect Excessive Account Lockouts" in container_name:
        workbook_name = "'POV_Excessive_Failed_Logons'"
        add_workbook(container, workbook_name)
        phantom.debug("Excessive Failed Logons Workbook Added")
        
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
