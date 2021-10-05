"""
This preflight playbook discovers the properties of the email and how it has been forwarded. Then it renames artifacts, extracts .msg attachments if needed, creates new phish reporter artifact, and sets the event label to 'phishing_email' ready for the POV_Phishing_Investigation workbook to be attached.
"""
import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block


# End - Global Code Block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'cf_local_POV_Email_Properties_1' block
    cf_local_POV_Email_Properties_1(container=container)

    return

"""
Work through the artifacts discerning as much information as we can about it, and setting up the properties so we can make decisions in downstream playbooks.
"""
def cf_local_POV_Email_Properties_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('cf_local_POV_Email_Properties_1() called')

    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in container_property_0:
        parameters.append({
            'container_id': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...



    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/POV_Email_Properties", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/POV_Email_Properties', parameters=parameters, name='cf_local_POV_Email_Properties_1', callback=GetEmailProperties)

    return

def GetEmailProperties(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('GetEmailProperties() called')
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_Email_Properties_1:custom_function_result.data'], action_results=results)
    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    GetEmailProperties__phish_artifact_id = None
    GetEmailProperties__forwarded_artifact_id = None
    GetEmailProperties__vaultIdForExecutable = None
    GetEmailProperties__hasRanPreviously = None
    GetEmailProperties__hasMSGFileAttached = None
    GetEmailProperties__isEMLForwarded = None
    GetEmailProperties__isMSGForwarded = None
    GetEmailProperties__vaultHasPossibleExecutable = None
    GetEmailProperties__vaultArtifactWithExecutable = None
    GetEmailProperties__randomSID = None
    GetEmailProperties__phishing_reporter = None
    GetEmailProperties__phishing_sourceUserName = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import string
    import random
    
    def get_random_string(length):
        
        letters = string.ascii_letters
        result_str = ''.join(random.choice(letters) for i in range(length))
        
        return result_str

    GetEmailProperties__randomSID  = get_random_string(20)

    try:
        custom_function_results_item_1_0[0]['phish_artifact_id']
        GetEmailProperties__phish_artifact_id = custom_function_results_item_1_0[0]['phish_artifact_id']
    except:
        GetEmailProperties__phish_artifact_id = None
    
    try:
        custom_function_results_item_1_0[0]['forwarded_artifact_id']
        GetEmailProperties__forwarded_artifact_id = custom_function_results_item_1_0[0]['forwarded_artifact_id']
    except:
        GetEmailProperties__forwarded_artifact_id = None
    
    try:
        custom_function_results_item_1_0[0]['vaultIdForExecutable']
        GetEmailProperties__vaultIdForExecutable = custom_function_results_item_1_0[0]['vaultIdForExecutable']
    except:
        GetEmailProperties__vaultIdForExecutable = None
        
    try:
        custom_function_results_item_1_0[0]['hasRanPreviously']
        GetEmailProperties__hasRanPreviously = custom_function_results_item_1_0[0]['hasRanPreviously']
    except:
        GetEmailProperties__hasRanPreviously = None

    try:
        custom_function_results_item_1_0[0]['hasMSGFileAttached']
        GetEmailProperties__hasMSGFileAttached = custom_function_results_item_1_0[0]['hasMSGFileAttached']
    except:
        GetEmailProperties__hasMSGFileAttached = None

    try:
        custom_function_results_item_1_0[0]['isEMLForwarded']
        GetEmailProperties__isEMLForwarded = custom_function_results_item_1_0[0]['isEMLForwarded']
    except:
        GetEmailProperties__isEMLForwarded = None  
        
    try:
        custom_function_results_item_1_0[0]['isMSGForwarded']
        GetEmailProperties__isMSGForwarded = custom_function_results_item_1_0[0]['isMSGForwarded']
    except:
        GetEmailProperties__isMSGForwarded = None   

    try:
        custom_function_results_item_1_0[0]['vaultHasPossibleExecutable']
        GetEmailProperties__vaultHasPossibleExecutable = custom_function_results_item_1_0[0]['vaultHasPossibleExecutable']
    except:
        GetEmailProperties__vaultHasPossibleExecutable = None     
        
    try:
        custom_function_results_item_1_0[0]['vaultArtifactWithExecutable']
        GetEmailProperties__vaultArtifactWithExecutable = custom_function_results_item_1_0[0]['vaultArtifactWithExecutable']
    except:
        GetEmailProperties__vaultArtifactWithExecutable = None
        
    try:
        custom_function_results_item_1_0[0]['phishing_reporter']
        GetEmailProperties__phishing_reporter = custom_function_results_item_1_0[0]['phishing_reporter']
        
    except:
        GetEmailProperties__phishing_reporter = None

    try:
        GetEmailProperties__phishing_sourceUserName = GetEmailProperties__phishing_reporter[:GetEmailProperties__phishing_reporter.index('@')]
    except:
        GetEmailProperties__phishing_sourceUserName = None
        
    ####

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='GetEmailProperties:phish_artifact_id', value=json.dumps(GetEmailProperties__phish_artifact_id))
    phantom.save_run_data(key='GetEmailProperties:forwarded_artifact_id', value=json.dumps(GetEmailProperties__forwarded_artifact_id))
    phantom.save_run_data(key='GetEmailProperties:vaultIdForExecutable', value=json.dumps(GetEmailProperties__vaultIdForExecutable))
    phantom.save_run_data(key='GetEmailProperties:hasRanPreviously', value=json.dumps(GetEmailProperties__hasRanPreviously))
    phantom.save_run_data(key='GetEmailProperties:hasMSGFileAttached', value=json.dumps(GetEmailProperties__hasMSGFileAttached))
    phantom.save_run_data(key='GetEmailProperties:isEMLForwarded', value=json.dumps(GetEmailProperties__isEMLForwarded))
    phantom.save_run_data(key='GetEmailProperties:isMSGForwarded', value=json.dumps(GetEmailProperties__isMSGForwarded))
    phantom.save_run_data(key='GetEmailProperties:vaultHasPossibleExecutable', value=json.dumps(GetEmailProperties__vaultHasPossibleExecutable))
    phantom.save_run_data(key='GetEmailProperties:vaultArtifactWithExecutable', value=json.dumps(GetEmailProperties__vaultArtifactWithExecutable))
    phantom.save_run_data(key='GetEmailProperties:randomSID', value=json.dumps(GetEmailProperties__randomSID))
    phantom.save_run_data(key='GetEmailProperties:phishing_reporter', value=json.dumps(GetEmailProperties__phishing_reporter))
    phantom.save_run_data(key='GetEmailProperties:phishing_sourceUserName', value=json.dumps(GetEmailProperties__phishing_sourceUserName))
    ifMSGFileAttached(container=container)
    ifRanPreviously(container=container)
    ifVaultHasExe(container=container)
    ifPhishReporter(container=container)

    return

def RenamePhishArtifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('RenamePhishArtifact() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    GetEmailProperties__phish_artifact_id = json.loads(phantom.get_run_data(key='GetEmailProperties:phish_artifact_id'))
    # collect data for 'RenamePhishArtifact' call

    parameters = []
    
    # build parameters list for 'RenamePhishArtifact' call
    parameters.append({
        'data': "{\"name\": \"Phishing Artifact\"}",
        'overwrite': True,
        'artifact_id': GetEmailProperties__phish_artifact_id,
    })

    phantom.act(action="update artifact fields", parameters=parameters, assets=['phantomapp'], callback=filter_2, name="RenamePhishArtifact")

    return

def RenameForwardingArtifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('RenameForwardingArtifact() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    GetEmailProperties__forwarded_artifact_id = json.loads(phantom.get_run_data(key='GetEmailProperties:forwarded_artifact_id'))
    # collect data for 'RenameForwardingArtifact' call

    parameters = []
    
    # build parameters list for 'RenameForwardingArtifact' call
    parameters.append({
        'data': "{\"name\": \"Forwarding Artifact\"}",
        'overwrite': True,
        'artifact_id': GetEmailProperties__forwarded_artifact_id,
    })

    phantom.act(action="update artifact fields", parameters=parameters, assets=['phantomapp'], name="RenameForwardingArtifact")

    return

"""
If we have identified the forwarding artifact id, rename the artifact
"""
def ifForwardedArtifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ifForwardedArtifact() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetEmailProperties:custom_function:forwarded_artifact_id", "!=", None],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        RenameForwardingArtifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def extractMSGFile(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('extractMSGFile() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'extractMSGFile' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'extractMSGFile' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'label': "",
                'vault_id': container_item[0],
                'container_id': id_value,
                'artifact_name': "Phishing Artifact",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="extract email", parameters=parameters, assets=['msg-parser'], callback=setEventLabel, name="extractMSGFile")

    return

"""
filter Vault Artifacts
"""
def filterVaultArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('filterVaultArtifacts() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.name", "==", "Vault Artifact"],
        ],
        name="filterVaultArtifacts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        GetMSGArtifactVaultId(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Searches Vault Artifacts for a fileName that ends in .msg, and returns the vaultId
"""
def GetMSGArtifactVaultId(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('GetMSGArtifactVaultId() called')
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filterVaultArtifacts:condition_1:artifact:*.cef'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    GetMSGArtifactVaultId__isMSGArtifact = None
    GetMSGArtifactVaultId__vaultId = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    phantom.debug(filtered_artifacts_item_1_0)
    
    for artifact in filtered_artifacts_item_1_0:
        msgFile = re.search("\.msg$", artifact['fileName'])
        if msgFile != None:
            phantom.debug('Found MSG Artifact')
            phantom.debug('setting vaultId to : {}'.format(artifact['vaultId']))
            GetMSGArtifactVaultId__isMSGArtifact = True
            GetMSGArtifactVaultId__vaultId = artifact['vaultId']
            
        else:
            GetMSGArtifactVaultId__isMSGArtifact = False
            phantom.debug('Not the MSG Artifact')

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='GetMSGArtifactVaultId:isMSGArtifact', value=json.dumps(GetMSGArtifactVaultId__isMSGArtifact))
    phantom.save_run_data(key='GetMSGArtifactVaultId:vaultId', value=json.dumps(GetMSGArtifactVaultId__vaultId))
    ifVaultIdReturned(container=container)

    return

"""
If we discovered a vaultId then extract the .msg file.
"""
def ifVaultIdReturned(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ifVaultIdReturned() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetMSGArtifactVaultId:custom_function:isMSGArtifact", "==", True],
            ["GetMSGArtifactVaultId:custom_function:vaultId", "!=", None],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        extractMSGFile(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Sets the event label to 'phishing_email' ready for downstream playbooks to work from
"""
def setEventLabel(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('setEventLabel() called')

    phantom.set_label(container=container, label="phishing_email")

    return

"""
Sets the event label to 'phishing_email' ready for downstream playbooks to work from
"""
def setEventLabel1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('setEventLabel1() called')

    phantom.set_label(container=container, label="phishing_email")

    return

"""
Rename 'Vault Artifact' to 'Vault Artifact - Executable' and set the severity to high for downstream playbooks
"""
def updateVaultArtifactName(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('updateVaultArtifactName() called')
    GetEmailProperties__vaultArtifactWithExecutable = json.loads(phantom.get_run_data(key='GetEmailProperties:vaultArtifactWithExecutable'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    parameters = []
    
    for artifact_id in GetEmailProperties__vaultArtifactWithExecutable:
        phantom.debug(artifact_id)

        # build parameters list for 'update_artifact_fields_4' call
        parameters.append({
            'data': "{\"name\":\"Vault Artifact - Executable\", \"severity\":\"high\"}",
            'overwrite': True,
            'artifact_id': artifact_id,
        })

        phantom.act(action="update artifact fields", parameters=parameters, assets=['phantomapp'], name="updateVaultName")

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

"""
If the event has POSSIBLE executable files, rename the artifact and increase severity to high
"""
def ifVaultHasExe(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ifVaultHasExe() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetEmailProperties:custom_function:vaultHasPossibleExecutable", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        updateVaultArtifactName(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
If No 'Email Artifacts' are found, we make the assumption this is not the first time the code ran, so won't try and rerun it.
"""
def ifRanPreviously(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ifRanPreviously() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetEmailProperties:custom_function:hasRanPreviously", "==", None],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        ifForwardedArtifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        ifPhishArtifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Checks if we identified an MSG file attached in the vault. if So, we'll go ahead and extract it
"""
def ifMSGFileAttached(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ifMSGFileAttached() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetEmailProperties:custom_function:hasMSGFileAttached", "!=", None],
            ["GetEmailProperties:custom_function:hasRanPreviously", "==", None],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        filterVaultArtifacts(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
If we have identified the phish email artifact rename it to phishing artifact
"""
def ifPhishArtifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ifPhishArtifact() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetEmailProperties:custom_function:phish_artifact_id", "!=", None],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        RenamePhishArtifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Add New artifact with the phishing reporters mail address
"""
def addPhishReporterArtifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('addPhishReporterArtifact() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    GetEmailProperties__phishing_reporter = json.loads(phantom.get_run_data(key='GetEmailProperties:phishing_reporter'))
    id_value = container.get('id', None)

    GetEmailProperties__randomSID = json.loads(phantom.get_run_data(key='GetEmailProperties:randomSID'))
    # collect data for 'addPhishReporterArtifact' call

    parameters = []
    
    # build parameters list for 'addPhishReporterArtifact' call
    parameters.append({
        'name': "Phishing Reporter",
        'label': "artifact",
        'cef_name': "fromEmail",
        'contains': "email",
        'cef_value': GetEmailProperties__phishing_reporter,
        'container_id': id_value,
        'cef_dictionary': "",
        'run_automation': "true",
        'source_data_identifier': GetEmailProperties__randomSID,
    })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantomapp'], name="addPhishReporterArtifact")

    return

"""
If we have identifed the sender of the email to phishing pond, we'll go ahead and create an artifact specifically with the email address of the sender.
"""
def ifPhishReporter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('ifPhishReporter() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["GetEmailProperties:custom_function:phishing_reporter", "!=", None],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        addPhishReporterArtifact(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def AddSenderEmail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('AddSenderEmail() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    getEmailAddress__formattedCef = json.loads(phantom.get_run_data(key='getEmailAddress:formattedCef'))
    GetEmailProperties__phish_artifact_id = json.loads(phantom.get_run_data(key='GetEmailProperties:phish_artifact_id'))
    # collect data for 'AddSenderEmail' call

    parameters = []
    
    # build parameters list for 'AddSenderEmail' call
    parameters.append({
        'data': getEmailAddress__formattedCef,
        'overwrite': True,
        'artifact_id': GetEmailProperties__phish_artifact_id,
    })

    phantom.act(action="update artifact fields", parameters=parameters, assets=['phantomapp'], callback=setEventLabel1, name="AddSenderEmail")

    return

def getEmailAddress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('getEmailAddress() called')
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.fromEmail'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    getEmailAddress__originalSenderEmail = None
    getEmailAddress__formattedCef = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(filtered_artifacts_item_1_0[0])
    import re
    x = re.search("(\<)(.*)(\>)", filtered_artifacts_item_1_0[0])
    if x: 
        getEmailAddress__originalSenderEmail = x.group(2)
        str = "{\"cef\": {\"originalSendingEmailFrom\": \"" + x.group(2) + "\"}}"
        getEmailAddress__formattedCef = str
    else:
        getEmailAddress__originalSenderEmail = None

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='getEmailAddress:originalSenderEmail', value=json.dumps(getEmailAddress__originalSenderEmail))
    phantom.save_run_data(key='getEmailAddress:formattedCef', value=json.dumps(getEmailAddress__formattedCef))
    AddSenderEmail(container=container)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.name", "==", "Phishing Artifact"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        getEmailAddress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return