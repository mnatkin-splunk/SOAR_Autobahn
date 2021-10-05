"""
This Playbook  runs the 3rd task of the  current phase , reviews the IOC Analysis notes, prompts analyst to categorize the email under investigation, sends the email to reporter accordingly, adds notes and completes the task.
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
    
    # call 'SetEventOwner' block
    SetEventOwner(container=container)

    return

"""
use task update parameter next_playbook to automatically update the next playbook called.

Custom code:

task_update__next_playbook = json.loads(phantom.get_run_data(key='task_update:next_playbook'))
    
    if task_update__next_playbook:    
        # call playbook "local/Set Priority", returns the playbook_run_id
        playbook_run_id = phantom.playbook(task_update__next_playbook, container=container)
    else:
        phantom.error("No playbook was found in the next task, reverting to manual mode")
"""
def call_next_playbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('call_next_playbook() called')
    task_update__next_playbook = json.loads(phantom.get_run_data(key='task_update:next_playbook'))
    
    if task_update__next_playbook:    
        # call playbook "local/Review Indicators", returns the playbook_run_id
        playbook_run_id = phantom.playbook(task_update__next_playbook, container=container)
    else:
        phantom.error("No playbook was found in the next task, reverting to manual mode")
    return

def Check_analyst_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Check_analyst_response() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["AnalystManualReviewPrompt:action_result.summary.responses.0", "==", "Phishing"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        phishing_email_tag(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["AnalystManualReviewPrompt:action_result.summary.responses.0", "==", "Spam"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        spam_email_tag(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    clean_email_tag(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Put Dynamic Email Recipient in production - filtered-data:filter_reporter_artifact:condition_1:artifact:*.cef.phishing_reporter
"""
def email_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('email_response() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'email_response' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filterPhishingReporter:condition_1:artifact:*.cef.fromEmail', 'filtered-data:filterPhishingReporter:condition_1:artifact:*.id'])
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['emailResponseTemplate:custom_function_result.data.response_email_body'], action_results=results)

    parameters = []
    
    # build parameters list for 'email_response' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        for custom_function_results_item_1 in custom_function_results_data_1:
            if filtered_artifacts_item_1[0] and custom_function_results_item_1[0]:
                parameters.append({
                    'cc': "",
                    'to': filtered_artifacts_item_1[0],
                    'bcc': "",
                    'body': custom_function_results_item_1[0],
                    'from': "",
                    'headers': "",
                    'subject': "Phish Alert Determination",
                    'attachments': "",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': filtered_artifacts_item_1[1]},
                })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=decision_8, name="email_response")

    return

def verify_analyst_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('verify_analyst_response() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["AnalystManualReviewPrompt:action_result.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Check_analyst_response(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    SLA_missed_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def SLA_missed_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SLA_missed_comment() called')

    phantom.comment(container=container, comment="Playbook didn't get Analyst Response  or SLA expired. Please complete manually.")
    CompleteTaskFailed(container=container)

    return

def clean_email_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('clean_email_tag() called')

    phantom.add_tags(container=container, tags="clean_email")
    join_filterPhishingArtifact(container=container)

    return

def phishing_email_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('phishing_email_tag() called')

    phantom.add_tags(container=container, tags="phishing_email")
    join_filterPhishingArtifact(container=container)

    return

def spam_email_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('spam_email_tag() called')

    phantom.add_tags(container=container, tags="spam_email")
    join_filterPhishingArtifact(container=container)

    return

"""
custom code :

Added drop_none=true in format action to filter all None values for phishing reporters.

Revised code - phantom.format(container=container, template=template, parameters=parameters,drop_none=True, name="format_task_notes")
"""
def format_task_notes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_task_notes() called')
    
    template = """#  {3} - Findings #

##Analyst's  Response for Phishing Identification :## {0}

**Additional Notes provided by Analyst:** {1}

**Phishing Response sent to :** {2}"""

    # parameter list for template variable replacement
    parameters = [
        "AnalystManualReviewPrompt:action_result.summary.responses.0",
        "AnalystManualReviewPrompt:action_result.summary.responses.1",
        "filtered-data:filterPhishingReporter:condition_1:artifact:*.cef.fromEmail",
        "cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_task_notes")

    add_note_9(container=container)

    return

def SetEventOwner(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('SetEventOwner() called')
    
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    container_property_0_0 = [item[0] for item in container_property_0]

    parameters.append({
        'container': container_property_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...



    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/POV_set_event_owner_to_current", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/POV_set_event_owner_to_current', parameters=parameters, name='SetEventOwner', callback=cf_local_POV_get_current_task_1)

    return

def cf_local_POV_get_current_task_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_POV_get_current_task_1() called')
    
    custom_function_result_0 = phantom.collect2(container=container, datapath=['SetEventOwner:custom_function_result.data.currentOwner'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    container_property_0_0 = [item[0] for item in container_property_0]
    custom_function_result_0_0 = [item[0] for item in custom_function_result_0]

    parameters.append({
        'container': container_property_0_0,
        'currentOwner': custom_function_result_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...



    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/POV_get_current_task", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/POV_get_current_task', parameters=parameters, name='cf_local_POV_get_current_task_1', callback=decision_5)

    return

def TaskInProgress(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('TaskInProgress() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'TaskInProgress' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['SetEventOwner:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'TaskInProgress' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "Task Started",
                'user': custom_function_results_item_1[0],
                'status': "in progress",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], callback=AnalystManualReviewPrompt, name="TaskInProgress")

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["cf_local_POV_get_current_task_1:custom_function_result.data.status", "==", "failed"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_comment_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    TaskInProgress(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def add_comment_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_7() called')

    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.message'], action_results=results)

    custom_function_results_item_1_0 = [item[0] for item in custom_function_results_data_1]

    phantom.comment(container=container, comment=custom_function_results_item_1_0)

    return

def AnalystManualReviewPrompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('AnalystManualReviewPrompt() called')
    username = phantom.collect2(container=container, datapath=['SetEventOwner:custom_function_result.data.username'], action_results=results)
    # set user and message variables for phantom.prompt call
    #user = "admin"
    user = username[0][0]
    phantom.debug('User set to: {}'.format(user))
    message = """Please take 15 mins to review the Task: {0}
Determine if Email is Phish, Spam or Clean and add any additional notes that should be included. complete{0}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_POV_get_current_task_1:custom_function_result.data.task_name",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Clean",
                    "Spam",
                    "Phishing",
                ]
            },
        },
        {
            "prompt": "Enter Analysis explanation. What data supports the decisions above?",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="AnalystManualReviewPrompt", parameters=parameters, response_types=response_types, callback=verify_analyst_response)

    return

def emailResponseTemplate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('emailResponseTemplate() called')
    
    filtered_artifacts_data_0 = phantom.collect2(container=container, datapath=['filtered-data:filterPhishingArtifact:condition_1:artifact:*.cef.emailHeaders.Date', 'filtered-data:filterPhishingArtifact:condition_1:artifact:*.cef.emailHeaders.Subject', 'filtered-data:filterPhishingArtifact:condition_1:artifact:*.cef.fromEmail'])
    action_results_data_0 = phantom.collect2(container=container, datapath=['AnalystManualReviewPrompt:action_result.summary.responses.0', 'AnalystManualReviewPrompt:action_result.parameter.context.artifact_id'], action_results=results )
    container_property_0 = [
        [
            container.get("id"),
        ],
    ]

    parameters = []

    for item0 in filtered_artifacts_data_0:
        for item1 in container_property_0:
            for item2 in action_results_data_0:
                parameters.append({
                    'email_date': item0[0],
                    'container_id': item1[0],
                    'determination': item2[0],
                    'email_subject': item0[1],
                    'external_sender': item0[2],
                })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...



    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/POV_phish_response_email_template", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/POV_phish_response_email_template', parameters=parameters, name='emailResponseTemplate', callback=ifTemplateCreatedOK)

    return

def CompleteTask(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CompleteTask() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'CompleteTask' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['SetEventOwner:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'CompleteTask' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "Task Completed",
                'user': custom_function_results_item_1[0],
                'status': "complete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="CompleteTask")

    return

def CompleteTaskFailed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CompleteTaskFailed() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'CompleteTaskFailed' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'CompleteTaskFailed' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        parameters.append({
            'note': "The SLA has been missed and therefore the customer has not had a response to the suspicious email.",
            'user': "",
            'status': "",
            'role_id': "",
            'task_id': custom_function_results_item_1[0],
            'task_name': "",
            'note_title': "Missed SLA - Customer Not Updated [ STATUS = FAILED ]",
            'phase_name': "",
            'container_id': "",
        })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="CompleteTaskFailed")

    return

def ifTemplateCreatedOK(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ifTemplateCreatedOK() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["emailResponseTemplate:custom_function_result.data.status", "==", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        filterPhishingReporter(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    FailedEmail(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def CompleteTaskwithExceptions(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('CompleteTaskwithExceptions() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'CompleteTaskwithExceptions' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['SetEventOwner:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'CompleteTaskwithExceptions' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "Unable to build the email body - Please check",
                'user': custom_function_results_item_1[0],
                'status': "complete",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': "",
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="CompleteTaskwithExceptions")

    return

def add_note_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_9() called')

    formatted_data_1 = phantom.get_format_data(name='format_task_notes')

    note_title = "Review Indicators"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)
    CompleteTask(container=container)

    return

def filterPhishingArtifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filterPhishingArtifact() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.name", "==", "Phishing Artifact"],
        ],
        name="filterPhishingArtifact:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        emailResponseTemplate(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def join_filterPhishingArtifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_filterPhishingArtifact() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_filterPhishingArtifact_called'):
        return

    # no callbacks to check, call connected block "filterPhishingArtifact"
    phantom.save_run_data(key='join_filterPhishingArtifact_called', value='filterPhishingArtifact', auto=True)

    filterPhishingArtifact(container=container, handle=handle)
    
    return

def filterPhishingReporter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filterPhishingReporter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.name", "==", "Phishing Reporter"],
        ],
        name="filterPhishingReporter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        email_response(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        format_task_notes(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def FailedEmail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('FailedEmail() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    id_value = container.get('id', None)

    # collect data for 'FailedEmail' call
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['SetEventOwner:custom_function_result.data.currentOwner'], action_results=results)
    custom_function_results_data_2 = phantom.collect2(container=container, datapath=['cf_local_POV_get_current_task_1:custom_function_result.data.task_id', 'cf_local_POV_get_current_task_1:custom_function_result.data.current_playbook_name'], action_results=results)

    parameters = []
    
    # build parameters list for 'FailedEmail' call
    for custom_function_results_item_1 in custom_function_results_data_1:
        for custom_function_results_item_2 in custom_function_results_data_2:
            parameters.append({
                'note': "Custom Function Failed - Email to the customer has not been sent",
                'user': custom_function_results_item_1[0],
                'status': "",
                'role_id': "",
                'task_id': custom_function_results_item_2[0],
                'task_name': "",
                'note_title': custom_function_results_item_2[1],
                'phase_name': "",
                'container_id': id_value,
            })

    phantom.act(action="update task", parameters=parameters, assets=['phantomapp'], name="FailedEmail")

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["email_response:action_result.status", "!=", "success"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        CompleteTaskwithExceptions(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

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