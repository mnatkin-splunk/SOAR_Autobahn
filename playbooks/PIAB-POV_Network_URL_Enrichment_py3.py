"""
Sub-Playbook that filters artifacts for URLs, Domains, and IP Addresses. Uses whois API, URLScan.io and PassiveTotal to enrich indicators. If a malicious URL is discovered the artifact is updated and HUD card pinned to show the category and other information
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_Indicators' block
    filter_Indicators(container=container)

    return

def filter_Indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('filter_Indicators() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""],
        ],
        name="filter_Indicators:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        is_whitelisted_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def RequestURL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('RequestURL() called')
    
    template = """Processing RequestURL : 
%%
{0}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "FilterNoisyURLs:custom_function:requestURLsforExternalLookup",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="RequestURL")

    Processing_URL(container=container)

    return

def Processing_URL(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('Processing_URL() called')

    formatted_data_1 = phantom.get_format_data(name='RequestURL')

    phantom.comment(container=container, comment=formatted_data_1)
    detonateUrl(container=container)

    return

def is_whitelisted_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('is_whitelisted_url() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["custom_list:whitelisted_urls", "not in", "filtered-data:filter_Indicators:condition_1:artifact:*.cef.requestURL"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        FilterNoisyURLs(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def detonateUrl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('detonateUrl() called')

    FilterNoisyURLs__requestURLsforExternalLookup = json.loads(phantom.get_run_data(key='FilterNoisyURLs:requestURLsforExternalLookup'))
    # collect data for 'detonateUrl' call

    parameters = []
    
    # build parameters list for 'detonateUrl' call
    for url in FilterNoisyURLs__requestURLsforExternalLookup:
        parameters.append({
            'url': url,
            'private': False,
        })

    phantom.act(action="detonate url", parameters=parameters, assets=['urlscan'], name="detonateUrl",callback=detonateStatus)

    return

def CheckMaliciousFlag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('CheckMaliciousFlag() called')
    input_parameter_0 = ""

    CheckMaliciousFlag__urlscan_notables = None
    CheckMaliciousFlag__is_malicious = None
    CheckMaliciousFlag__hud_malicious_message = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    CheckMaliciousFlag__is_malicious = False
    
    GetReportData_results = phantom.get_action_results(action_name="GetReportData")
    if GetReportData_results:
        phantom.debug(GetReportData_results)
    
        urlscan_notables = {}

        urlscan_notables = json.dumps({"cef": {"urlscan_tags": GetReportData_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['tags'], 
                                 "urlscan_malicious": GetReportData_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['malicious'],
                                 "urlscan_verdict_score": GetReportData_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['score'],
                                 "urlscan_screenshotURL": GetReportData_results[0]['action_results'][0]['data'][0]['task']['screenshotURL']
        }})
        phantom.debug('URLNOTABLES: {}'.format(urlscan_notables))
        
        if GetReportData_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['malicious'] == True:
            CheckMaliciousFlag__is_malicious = True
            CheckMaliciousFlag__hud_malicious_message = "Malicious URL: " + str(GetReportData_results[0]['action_results'][0]['data'][0]['task']['url']) + " : Category " + str(GetReportData_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['tags'])

    deturl_results = phantom.get_action_results(action_name="detonateUrl")
    if deturl_results:
        urlscan_notables = {}
        #{"cef": {"covid_related": "yes"}}
        urlscan_notables = json.dumps({"cef": {"urlscan_tags": deturl_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['tags'], 
                                 "urlscan_malicious": deturl_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['malicious'],
                                 "urlscan_verdict_score": deturl_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['score'],
                                 "urlscan_screenshotURL": deturl_results[0]['action_results'][0]['data'][0]['task']['screenshotURL']
        }})
        phantom.debug('URLNOTABLES: {}'.format(urlscan_notables))

        if deturl_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['malicious'] == True:
            CheckMaliciousFlag__is_malicious = True
            CheckMaliciousFlag__hud_malicious_message = "Malicious URL: " + str(deturl_results[0]['action_results'][0]['data'][0]['task']['url']) + " : Category " + str(deturl_results[0]['action_results'][0]['data'][0]['verdicts']['urlscan']['tags'])

    phantom.debug('Notables: {}'.format(urlscan_notables))
    CheckMaliciousFlag__urlscan_notables = urlscan_notables
    #######################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='CheckMaliciousFlag:urlscan_notables', value=json.dumps(CheckMaliciousFlag__urlscan_notables))
    phantom.save_run_data(key='CheckMaliciousFlag:is_malicious', value=json.dumps(CheckMaliciousFlag__is_malicious))
    phantom.save_run_data(key='CheckMaliciousFlag:hud_malicious_message', value=json.dumps(CheckMaliciousFlag__hud_malicious_message))

    return

def update_artifact_fields_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('update_artifact_fields_1() called')

    CheckMaliciousFlag__urlscan_notables = json.loads(phantom.get_run_data(key='CheckMaliciousFlag:urlscan_notables'))
    # collect data for 'update_artifact_fields_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_Indicators:condition_1:artifact:*.id', 'filtered-data:filter_Indicators:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'update_artifact_fields_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'data': CheckMaliciousFlag__urlscan_notables,
                'overwrite': True,
                'artifact_id': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="update artifact fields", parameters=parameters, assets=['phantomapp'], name="update_artifact_fields_1")

    return

"""
Step through the top500 & whitelisted_urls custom list and remove any URLs found in there.
"""
def FilterNoisyURLs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('FilterNoisyURLs() called')
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_Indicators:condition_1:artifact:*.cef'])
    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    FilterNoisyURLs__requestURLsforExternalLookup = None
    FilterNoisyURLs__numURLs = None
    FilterNoisyURLs__removedURLs = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    nonMatchedArtifacts = []
    ignoredArtifacts = []
    phantom.debug(filtered_artifacts_item_1_0)
    import re
    from urllib.parse import urlparse
    success_wlist, message, urls = phantom.get_list(list_name='whitelisted_urls')
    success_top500, message, top500urls = phantom.get_list(list_name='top500')

    if success_wlist and success_top500:
        for artifact in filtered_artifacts_item_1_0:
            phantom.debug('Processing Artifact: {}'.format(artifact))
            requestURL = urlparse(artifact['requestURL']).netloc
            phantom.debug('requestURL before you fuck with it: {}'.format(requestURL))
            if re.match('www\.', requestURL):
                requestURL = '.'.join(requestURL.split('.')[1:])
                
            phantom.debug('requestURL after you fuck with it: {}'.format(requestURL))
            isNotInCustomList = 0
            willIgnore = 0
            
            # Check if the domain is in the whitelisted URLs list - Ignore if so
            for url in urls:
                str=url[0]
                if str == None:
                    continue
                
                if re.search(requestURL, str):
                    #phantom.debug('matching URL found: {} against {}'.format(requestURL,str))
                    phantom.debug('[+] Match Found (Whitelisted URL) - Will NOT be added - Finished Checking {}'.format(requestURL))
                    ignoredArtifacts.append(artifact['requestURL'])
                    willIgnore = 1
                    break

            # Do not check anymore - this URL will NOT be processed down the line        
            if willIgnore == 1:
                continue

            if willIgnore == 0:
                phantom.debug('[+] No Match found in the whitelisted URLS for: {}'.format(requestURL))
                
            # Now check the top500 list and ignore if found here.
            phantom.debug('[+] Checking top500 Loop for requestURL: {}'.format(requestURL))
            for top500url in top500urls:
                str=top500url[0]
                if str == None:
                    continue
                    
                if re.search(requestURL, str):
                    phantom.debug('[+] Match Found (top 500 Domain) - Will NOT be added - Finished Checking {}'.format(requestURL))
                    ignoredArtifacts.append(artifact['requestURL'])
                    willIgnore = 1
                    break

            if willIgnore == 0:
                nonMatchedArtifacts.append(artifact['requestURL'])
                phantom.debug('adding {} to the list'.format(artifact['requestURL']))

    phantom.debug('finished with: {}'.format(nonMatchedArtifacts))
    FilterNoisyURLs__requestURLsforExternalLookup = nonMatchedArtifacts
    FilterNoisyURLs__numURLs = len(nonMatchedArtifacts)
    FilterNoisyURLs__removedURLs = ignoredArtifacts
    phantom.debug('Ignored URLs: {}'.format(FilterNoisyURLs__removedURLs))
    phantom.debug('Passing out : {} URLs'.format(FilterNoisyURLs__numURLs))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='FilterNoisyURLs:requestURLsforExternalLookup', value=json.dumps(FilterNoisyURLs__requestURLsforExternalLookup))
    phantom.save_run_data(key='FilterNoisyURLs:numURLs', value=json.dumps(FilterNoisyURLs__numURLs))
    phantom.save_run_data(key='FilterNoisyURLs:removedURLs', value=json.dumps(FilterNoisyURLs__removedURLs))
    decision_9(container=container)

    return

def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["FilterNoisyURLs:custom_function:numURLs", "==", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_comment_12(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    RequestURL(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def detonateStatus(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('detonateStatus() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["detonateUrl:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_comment_add_note_11(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    parseScanIO(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_comment_add_note_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('add_comment_add_note_11() called')

    phantom.comment(container=container, comment="Detonate URL Action Failed - Check")

    note_title = "POV_Network_URL_Enrichment"
    note_content = "**Detonate URL Action Failed - Please Check**"
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_comment_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('add_comment_12() called')

    phantom.comment(container=container, comment="No URLs in the event require external lookup")
    NoLookupsFormatNote(container=container)

    return

def NoLookupsFormatNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('NoLookupsFormatNote() called')
    
    template = """## POV_Network_URL_Enrich ##

**Playbook Result**

No external URL lookups were conducted - Each URL is either in the top500 or globalconfig custom lists. No action required. 

For reference - these are the URLs in the container artifacts. 

| URL |
|---|
%%
| {0} |
%%"""

    # parameter list for template variable replacement
    parameters = [
        "FilterNoisyURLs:custom_function:removedURLs",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="NoLookupsFormatNote")

    add_note_13(container=container)

    return

def add_note_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('add_note_13() called')

    formatted_data_1 = phantom.get_format_data(name='NoLookupsFormatNote')

    note_title = "POV_Network_URL_Enrichment"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Parses the output from URLScan.io ready for generating the notes.
"""
def parseScanIO(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('parseScanIO() called')
    results_data_1 = phantom.collect2(container=container, datapath=['detonateUrl:action_result.data'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    parseScanIO__community = None
    parseScanIO__overall = None
    parseScanIO__engines = None
    parseScanIO__pincategory = None
    parseScanIO__screenshot_url = None
    parseScanIO__report_link = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    #phantom.debug(results_item_1_0)
    try:
        community = results_item_1_0[0][0]['verdicts']['community']
        phantom.debug('community: {}'.format(community))
        parseScanIO__community = str(community['votesMalicious']) + "|" + str(community['votesBenign']) + "|" + str(community['score']) + "|" + str(community['votesTotal']) + "|"
    except:
        parseScanIO__community = 'No Data'
    
    try:
        overall = results_item_1_0[0][0]['verdicts']['overall']
        phantom.debug('overall: {}'.format(overall))
        parseScanIO__overall = str(overall['malicious']) + "|" + str(overall['score']) + "|" + str(overall['hasVerdicts']) + "|" + str(overall['categories']) + "|" + str(overall['brands']) + "|"
    except:
        parseScanIO__overall = 'No Data'
        
    try:
        engines = results_item_1_0[0][0]['verdicts']['engines']
        phantom.debug('engines: {}'.format(engines))
        parseScanIO__engines = str(engines['verdicts']) + "|" + str(engines['malicious']) + "|" + str(engines['score']) + "|" + str(engines['maliciousTotal']) + "|" + str(engines['enginesTotal']) + "|"
    except:
        parseScanIO__engines = 'No Data'
        
    try:
        if len(results_item_1_0[0][0]['verdicts']['overall']['categories']) > 0:
            parseScanIO__pincategory = "|".join(results_item_1_0[0][0]['verdicts']['overall']['categories'])
        else:
            parseScanIO__pincategory = None
    except:
        parseScanIO__pincategory = None
        
    try:
        parseScanIO__screenshot_url = results_item_1_0[0][0]['task']['screenshotURL']
    except:
        parseScanIO__screenshot_url = None

    try:
        parseScanIO__report_link = results_item_1_0[0][0]['task']['reportURL']
    except:
        parseScanIO__report_link = None

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='parseScanIO:community', value=json.dumps(parseScanIO__community))
    phantom.save_run_data(key='parseScanIO:overall', value=json.dumps(parseScanIO__overall))
    phantom.save_run_data(key='parseScanIO:engines', value=json.dumps(parseScanIO__engines))
    phantom.save_run_data(key='parseScanIO:pincategory', value=json.dumps(parseScanIO__pincategory))
    phantom.save_run_data(key='parseScanIO:screenshot_url', value=json.dumps(parseScanIO__screenshot_url))
    phantom.save_run_data(key='parseScanIO:report_link', value=json.dumps(parseScanIO__report_link))
    formatNote(container=container)
    decision_11(container=container)

    return

"""
General Note for urlscan.io
"""
def formatNote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('formatNote() called')
    
    template = """## Result Links ##

** Report URL: ** {3}

** Screenshot URL: ** {4}

## Overall ##

|Malicious|Score|Verdicts|Categories|Brands|
|---|---|---|---|---|
{1}

## Engines ##

|Verdicts|Malicious|Score|MaliciousTotal|EnginesTotal|
|---|---|---|---|---|
{2}

## Community ##

|Malicious Votes|Benign Votes|Score|VotesTotal|
|---|---|---|---|
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "parseScanIO:custom_function:community",
        "parseScanIO:custom_function:overall",
        "parseScanIO:custom_function:engines",
        "parseScanIO:custom_function:report_link",
        "parseScanIO:custom_function:screenshot_url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="formatNote")

    urlScanIONote(container=container)

    return

def urlScanIONote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('urlScanIONote() called')

    formatted_data_1 = phantom.get_format_data(name='formatNote')

    note_title = "URL Scan Results"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('decision_11() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["parseScanIO:custom_function:pincategory", "!=", None],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        CategoryPin(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def CategoryPin(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('CategoryPin() called')

    parseScanIO__pincategory = json.loads(phantom.get_run_data(key='parseScanIO:pincategory'))

    phantom.pin(container=container, data=parseScanIO__pincategory, message="URL Scan Category", pin_type="card", pin_style="red", name=None)

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