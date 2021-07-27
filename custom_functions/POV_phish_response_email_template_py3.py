def POV_phish_response_email_template_py3(container_id=None, external_sender=None, email_subject=None, email_date=None, determination=None, **kwargs):
    """
    Based on a determination format an email template as phish, clean, spam.
    
    Args:
        container_id (CEF type: *)
        external_sender (CEF type: *)
        email_subject (CEF type: *)
        email_date (CEF type: *)
        determination (CEF type: *)
    
    Returns a JSON-serializable object that implements the configured data paths:
        response_email_body (CEF type: *)
        status (CEF type: *): success or failed
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    phantom.debug('Started - Dtermination: {}'.format(determination))
    determination = str(determination)
    
    # Clean Email Template
    def is_clean():
        phantom.debug('Email is Clean called')
        template = """Hello, 
        
In Reference to the suspected Phishing Email you sent:

Email Sender:  {0}
Email Subject:  {1}
Sent At:  {2}

Please see below analysis:

We have analyzed the email you reported and have determined it to be \"Legitimate\" (Clean). Should you have any questions please contact your Security Operations / IT Team using your normal contact details. 

Thank you for reporting a potential phishing email and continue to report any suspicious emails.

Splunk > Phantom
""".format(external_sender, email_subject,email_date)
        return template
        
    
    # Spam Email Template
    def is_spam():
        phantom.debug('Email is spam called')
        template = """Hello,
        
In Reference to the suspected Phishing Email you sent:

Email Sender:  {0}
Email Subject:  {1}
Sent At:  {2}

Please see below analysis:

We have analyzed the email you reported and have determined it to be \"Spam.\" If you no longer wish to receive future emails from this sender we recommend that you perform the following actions:

1.	Locate the original email that you reported, from \"Inbox\" or the \"Deleted Items\" folder.
2.	Right-click on the email, move your mouse pointer to \"Spam Emails\" and click on \"Block Sender.\". If you are not using Outlook, use your email program to block the sender. If you do not know how to do this, please call support in your usual way.

Should you have any questions please contact your Security Operations / IT Team using your normal contact details. 

Thank you for reporting a potential phishing email and continue to report any suspicious emails.

Splunk > Phantom
""".format(external_sender, email_subject,email_date)
        return template
        
    
    
    # Phishing Email Template
    def is_phishing():
        phantom.debug('Email is a Phish called')
        template = """Hello,
        
In Reference to the suspected Phishing Email you sent:

Email Sender:  {0}
Email Subject:  {1}
Sent At:  {2}

Please see below analysis:

We have analyzed the email you reported and have determined it to be a \"Phishing attack.\" If you no longer wish to receive future emails from this sender we recommend that you perform the following actions:

1.	Locate the original email that you reported, from \"Inbox\" or the \"Deleted Items\" folder.
2.	Right-click on the email, move your mouse pointer to \"Spam Emails\" and click on \"Block Sender.\". If you are not using Outlook, use your email program to block the sender. If you do not know how to do this, please call support in your usual way.

Should you have any questions please contact your Security Operations / IT Team using your normal contact details. 

Thank you for reporting a potential phishing email and continue to report any suspicious emails.

Splunk > Phantom
""".format(external_sender, email_subject,email_date)
        return template
    
    
    # *************************
    #    Main Code
    # *************************
    """
    # Check we have the right inputs
    if not determination:
        phantom.error('[+] No Determination set')
        outputs = { 'status':'failed' }
        return outputs
    else:
        determination = determination[0]
    """    
    
        
    if determination != "Spam" and determination != "Phishing" and determination != "Clean":
        phantom.error('[+] Determination is not set correctly')
        outputs = { 'status':'failed' }
        return outputs
        
    # Set some defaults
    if not external_sender:
        external_sender = '<_MISSING_DATA_>'
    if not email_subject:
        email_subject = '<_MISSING_DATA_>'
    if not email_date:
        email_date = '<_MISSING_DATA_>'
        
    
    #phantom.debug('[+] Args: external_sender: {0}, external_sender_name: {1}, email_subject: {2}, email_date: {3}'.format(external_sender, external_sender_name, email_subject,email_date))
    
    # Grab templated info from custom list to make this a configuration option.
    """
    success, message, globalconfig = phantom.get_list(list_name="globalconfig")
    email_footer = None
    for i in globalconfig:
        if i[0] == "email_footer":
            email_footer = i[1]
            phantom.debug('Found Email Footer - Set to {}'.format(email_footer))
            
    if email_footer == None:
        phantom.debug('Unable to find email_footer')
               
    
    phantom.debug('success: {0}, message: {1}, globalconfig: {2}'.format(success, message, globalconfig))
    phantom.debug(type(globalconfig))
    #email_footer = globalconfig[0]
    """
    
    # create template depending on determination
    if determination == "Clean":
        email_body = is_clean()
        
    elif determination == "Spam":
        email_body = is_spam()
        
    elif determination == "Phishing":
        email_body = is_phishing()
        
    outputs = {
        'response_email_body': email_body,
        'status':'success'
    }
    
    
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
