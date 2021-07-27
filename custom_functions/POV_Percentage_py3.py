def POV_Percentage_py3(numerator=None, denominator=None, **kwargs):
    """
    Calculates the percentage of two numbers.
    
    Args:
        numerator (CEF type: *): Numerator = Top of equation.
        denominator (CEF type: *): Denominator = the 'out of' score. 
    
    Returns a JSON-serializable object that implements the configured data paths:
        percentage_val (CEF type: *): Single Number
        percentage_str (CEF type: *): Includes the % symbol as text string
        status (CEF type: *): Function Status (success, failed)
        message (CEF type: *): Any failure message
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    percentage_val = 0
    percentage_str = None
    status = None
    message = None
    
    #phantom.debug('Numerator: {}: Denominator: {}'.format(numerator,denominator))
    
    if int(denominator) == 0:
        message = 'Division by zero attempted'
        status = 'failed'
        outputs = { 'status': status,
                   'message' : message
                  }
        
    if status == None:
        try:
            percentage_val = round((float(numerator)/denominator)*100,0)
            percentage_str = str(percentage_val) + "%"
            status = 'success'
        except Exception as e:
            message = e
            status = 'failed'
            phantom.error(message)
        
        outputs= {
            'percentage_val': percentage_val,
            'percentage_str': percentage_str,
            'message': message,
            'status': status
        }
        phantom.debug('outputs: {}'.format(outputs))
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
