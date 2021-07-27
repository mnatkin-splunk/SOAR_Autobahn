"""
This playbook populates a Splunk Search template from the globalconfig list key called 'siem_context_authentications_1' with the destinationHostName field and runs a search looking for successful logons and privilege escalations (4624 & 4648), then makes an assessment as to the logon type and direction, before writing a general note with the splunk data in table format.
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
    
    # call 'cf_local_POV_get_global_config_1' block
    cf_local_POV_get_global_config_1(container=container)

    return

"""
Run Splunk Query - Looking for Authentication Data
"""
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    formatSplunkSearch__splunk_auth_search_1 = json.loads(phantom.get_run_data(key='formatSplunkSearch:splunk_auth_search_1'))
    # collect data for 'run_query_1' call

    parameters = []
    
    # build parameters list for 'run_query_1' call
    parameters.append({
        'query': formatSplunkSearch__splunk_auth_search_1,
        'command': "search",
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=SplunKActionStatus, name="run_query_1")

    return

def cf_local_POV_get_global_config_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_POV_get_global_config_1() called')
    
    literal_values_0 = [
        [
            "siem_context_authentication_by_host_1",
        ],
    ]

    parameters = []

    for item0 in literal_values_0:
        parameters.append({
            'return_keys': item0[0],
        })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...



    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/POV_get_global_config", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/POV_get_global_config', parameters=parameters, name='cf_local_POV_get_global_config_1', callback=ifsuccess)

    return

"""
Read the template search from globalconfig and add the originating host. Defaults to -24h if no field called firstTime exists in the artifact.
"""
def formatSplunkSearch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatSplunkSearch() called')
    
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_global_config_1:custom_function_result.data.*.siem_context_authentication_1'], action_results=results)
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filterArtifacts:condition_1:artifact:*.cef.destinationHostName', 'filtered-data:filterArtifacts:condition_1:artifact:*.cef.firstTime', 'filtered-data:filterArtifacts:condition_1:artifact:*.cef.lastTime'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_1 = [item[1] for item in filtered_artifacts_data_1]
    filtered_artifacts_item_1_2 = [item[2] for item in filtered_artifacts_data_1]
    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    formatSplunkSearch__splunk_auth_search_1 = None
    formatSplunkSearch__status = None
    formatSplunkSearch__message = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import time
    t = None
    earliest = None
    latest = None
    dest_host = None
    
    # If missing template or input strings
    if custom_function_results_item_1_0[0] == "None" or filtered_artifacts_item_1_0[0] == "None":
        phantom.error('Missing Fields: TemplateSearch: {}, Replacement: {}'.format(custom_function_results_item_1_0[0],filtered_artifacts_item_1_0[0]))
        formatSplunkSearch__status = 'failed'
        formatSplunkSearch__message = 'Fields Missing'
        return

    earliest = filtered_artifacts_item_1_1[0]
    dest_host = filtered_artifacts_item_1_0[0]
    
    now = time.time()
    latest = now
    
    phantom.debug('Setting earliest var for Splunk search - defaults to -24h if none passed, and passed var -30 mins if firstTime var passed in.')
    # No firstTime field present Default to -24hours. (Container time might be better....)
    if earliest == None:
        phantom.debug('No firstTIme field presented - defaulting to now -24h')
        t = time.gmtime()
        t = time.mktime(t)
        earliest = t - 86400
    
    # if ctime formatted string passed.
    if type(earliest) == str:
        phantom.debug('Formatted Date String Passed - Converting to EPOCH using strptime format %m/%d/%Y %H:%M:%S')
        t = time.strptime(earliest, "%m/%d/%Y %H:%M:%S")
        earliest = time.mktime(t) - 1800
        
    elif type(earliest) == float:
        phantom.debug('Date Passed as EPOCH')
        earliest = earliest - 1800
    else:
        phantom.error('Unable to determine the date format - Does not appear as empty, str or epoch...')
        formatSplunkSearch__status = 'failed'
        formatSplunkSearch__message = 'Unable to determine the date format - Does not appear as empty, str or epoch...'
    
    try:             
        template_search = str(custom_function_results_item_1_0[0])
        formatSplunkSearch__splunk_auth_search_1 = template_search.format(str(dest_host),str(earliest),str(latest))
        phantom.debug(formatSplunkSearch__splunk_auth_search_1)
        formatSplunkSearch__status = 'success'
    except Exception as e:
        phantom.error('Unable to create Splunk Auth Search: {}'.format(e))
        formatSplunkSearch__status = 'failed'
        formatSplunkSearch__message = e

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='formatSplunkSearch:splunk_auth_search_1', value=json.dumps(formatSplunkSearch__splunk_auth_search_1))
    phantom.save_run_data(key='formatSplunkSearch:status', value=json.dumps(formatSplunkSearch__status))
    phantom.save_run_data(key='formatSplunkSearch:message', value=json.dumps(formatSplunkSearch__message))
    checkStatus(container=container)

    return

"""
Checks the output from get key block
"""
def ifsuccess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ifsuccess() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_get_global_config_1:custom_function_result.success", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        CommentNoConfig(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filterArtifacts(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Add comment, globalconfig custom list can't find the key 'siem_context_authentication_1' 
"""
def CommentNoConfig(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CommentNoConfig() called')

    phantom.comment(container=container, comment="Unable to find key siem_context_authentication_1 in globalconfig customlist")

    return

def filterArtifacts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filterArtifacts() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationHostName", "!=", ""],
        ],
        name="filterArtifacts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        formatSplunkSearch(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Checks the output status of the previous block.
"""
def checkStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('checkStatus() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["formatSplunkSearch:custom_function:status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_comment_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    run_query_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_2() called')

    phantom.comment(container=container, comment="Unable to create Splunk Authentication Search - Please Check.")

    return

"""
Checks the output of the Splunk Action Status. 
"""
def SplunKActionStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SplunKActionStatus() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["run_query_1:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_comment_add_note_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    formatSplunkResults(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Action Failure General Note and Comment
"""
def add_comment_add_note_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_add_note_3() called')

    results_data_1 = phantom.collect2(container=container, datapath=['run_query_1:action_result.message'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.comment(container=container, comment="SplunkQuery Failed to execute")

    note_title = "SplunkQuery Failure"
    note_content = results_item_1_0
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Formats the Splunk Output ready for General Notes.
"""
def formatSplunkResults(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('formatSplunkResults() called')
    
    template = """#  POV_SIEM_Context_Authentication_By_Host  - Findings #

** Query Ran: **  {0}

** Total Results Returned: ** {2}

** Result Message: ** {1}

|_time| Host | EventCode | TargetDomain | TargetUserName | Logon Type | srcAddress | SubjectUserName | TargetServerName | Direction |
|---|---|---|---|---|---|---|---|---|---|
%%
|{3}|{4}|{5}|{6}|{7}|{8}|{9}|{10}|{11}|{12}|
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_query_1:action_result.parameter.query",
        "run_query_1:action_result.message",
        "run_query_1:action_result.summary.total_events",
        "run_query_1:action_result.data.*._time",
        "run_query_1:action_result.data.*.host",
        "run_query_1:action_result.data.*.EventCode",
        "run_query_1:action_result.data.*.Target_Domain",
        "run_query_1:action_result.data.*.TargetUserName",
        "run_query_1:action_result.data.*.LogonType",
        "run_query_1:action_result.data.*.srcAddress",
        "run_query_1:action_result.data.*.SubjectUserName",
        "run_query_1:action_result.data.*.TargetServerName",
        "run_query_1:action_result.data.*.direction",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatSplunkResults")

    GeneralNote(container=container)

    return

"""
Add General Notes
"""
def GeneralNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('GeneralNote() called')

    formatted_data_1 = phantom.get_format_data(name='formatSplunkResults')

    note_title = "POV_SIEM_Context_Authentication_By_Host"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

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