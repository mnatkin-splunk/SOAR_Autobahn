"""
This playbook should be run as a sub-playbook at the end of automation to report its findings. It is an example of how Phantom can be used to generate tickets.
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
    
    # call 'getTicketingOutputs' block
    getTicketingOutputs(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["getTicketingOutputs:custom_function:servicenow", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        checkServiceNowFields(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def checkServiceNowFields(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('checkServiceNowFields() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug('ServiceNow')

    ################################################################################
    ## Custom Code End
    ################################################################################
    create_ServiceNow_ticket(container=container)

    return

def checkEmailFields(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('checkEmailFields() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug('oops')

    ################################################################################
    ## Custom Code End
    ################################################################################
    send_email_1(container=container)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["getTicketingOutputs:custom_function:getTicketingOutput", "==", "badValue"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Comment_Misconfigured_List(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    decision_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    decision_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    decision_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Comment_Misconfigured_List(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Comment_Misconfigured_List() called')

    phantom.comment(container=container, comment="Custom list not configured, or badly configured")

    return

def checkJira(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('checkJira() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################
    create_JIRA_ticket(container=container)

    return

def create_JIRA_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_JIRA_ticket() called')

    name_value = container.get('name', None)

    # collect data for 'create_JIRA_ticket' call

    parameters = []
    
    # build parameters list for 'create_JIRA_ticket' call
    parameters.append({
        'fields': "",
        'summary': name_value,
        'assignee': "",
        'priority': "",
        'vault_id': "",
        'issue_type': "Request new software",
        'description': "Phantom Handled this ticket",
        'project_key': "PRIN",
        'assignee_account_id': "",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['jiraingest'], callback=JIRA_Status_Message, name="create_JIRA_ticket")

    return

def create_ServiceNow_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ServiceNow_ticket() called')

    name_value = container.get('name', None)

    # collect data for 'create_ServiceNow_ticket' call

    parameters = []
    
    # build parameters list for 'create_ServiceNow_ticket' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': "Phantom Handled The EC2 Issue",
        'short_description': name_value,
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=ServiceNow_Status_Message, name="create_ServiceNow_ticket")

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_1() called')

    name_value = container.get('name', None)

    # collect data for 'send_email_1' call

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'cc': "",
        'to': "deking@splunk.com",
        'bcc': "",
        'body': "Phantom Handled the ticket",
        'from': "phantom@attackrange.local",
        'headers': "",
        'subject': name_value,
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=Email_Status_Message, name="send_email_1")

    return

def ServiceNow_Status_Message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ServiceNow_Status_Message() called')
    
    template = """ServiceNow Ticket Creation status : {0}"""

    # parameter list for template variable replacement
    parameters = [
        "create_ServiceNow_ticket:action_result.status",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="ServiceNow_Status_Message")

    add_comment_5(container=container)

    return

def add_comment_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_5() called')

    formatted_data_1 = phantom.get_format_data(name='ServiceNow_Status_Message')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def JIRA_Status_Message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('JIRA_Status_Message() called')
    
    template = """JIRA Ticket Creation status : {0}"""

    # parameter list for template variable replacement
    parameters = [
        "create_JIRA_ticket:action_result.status",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="JIRA_Status_Message")

    add_comment_7(container=container)

    return

def Email_Status_Message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Email_Status_Message() called')
    
    template = """Email Ticket Creation status : {0}"""

    # parameter list for template variable replacement
    parameters = [
        "send_email_1:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Email_Status_Message")

    add_comment_6(container=container)

    return

def add_comment_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_6() called')

    formatted_data_1 = phantom.get_format_data(name='Email_Status_Message')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def add_comment_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_7() called')

    formatted_data_1 = phantom.get_format_data(name='JIRA_Status_Message')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def getTicketingOutputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('getTicketingOutputs() called')
    
    input_parameter_0 = ""

    getTicketingOutputs__getTicketingOutput = None
    getTicketingOutputs__servicenow = None
    getTicketingOutputs__jira = None
    getTicketingOutputs__email = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    success, message, results = phantom.get_list(list_name="globalconfig", values="ticketing", trace=False)
    phantom.debug('Printing success: {0}, message: {1}, results: {2}, '.format(success, message, results))
    
    ticketing_app = results['matches'][0]['value'][1]
    if not "servicenow" or not "jira" or not "email" in ticketing_app:
        getTicketOutput = "badValue"
        phantom.debug('TicketingApp: BadValue - Check global config custom list')
        return
    
    servicenow,email,jira = 0,0,0
    
    if "servicenow" in ticketing_app:
        getTicketingOutputs__servicenow = 1
    
    if "jira" in ticketing_app:
        getTicketingOutputs__jira = 1
    
    if "email" in ticketing_app:
        getTicketingOutputs__email = 1
    
    #phantom.debug('Ticketing App set to: {}'.format(getTicketingOutputs__getTicketingOutput)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='getTicketingOutputs:getTicketingOutput', value=json.dumps(getTicketingOutputs__getTicketingOutput))
    phantom.save_run_data(key='getTicketingOutputs:servicenow', value=json.dumps(getTicketingOutputs__servicenow))
    phantom.save_run_data(key='getTicketingOutputs:jira', value=json.dumps(getTicketingOutputs__jira))
    phantom.save_run_data(key='getTicketingOutputs:email', value=json.dumps(getTicketingOutputs__email))
    decision_2(container=container)

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["getTicketingOutputs:custom_function:jira", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        checkJira(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["getTicketingOutputs:custom_function:email", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        checkEmailFields(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
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