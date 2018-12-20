
# encoding = utf-8
def query_url(helper, album_id, themethod):
    import json
    import re, urllib
    from httplib2 import Http
    
    if not album_id:
        helper.log_error('Some parameters are missing. The required are: album ID.')
        return

    uri = 'https://api.spotify.com/v1/albums/'+album_id+'/tracks'
    http = helper.build_http_connection(helper.proxy, timeout=30)
    data = {
        'album_id': '{}'.format(album_id)
    }
     #No headers needed in this case
    headers = {
    #'header1' : 'header_value'
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer BQBYBhSi4xMxA4ZWoFcgJzVCat1Bi8L9a04ivww0O1dt7d89A8nQeHJO84YOXIc8t7bHOyChZCKZG_OMGm4cTdO0LZM05df5nd4lZdvnIQK72yydJCOmxo6X6Pi8kuufMmUwiZ1Vtp3iOrjU862brslyHEB-cAG8QzC4EGyYNQ_o7NcIu2nNZhQO0tvG3zW_Az53GixqsaBcIgQoV76CZu7ojdk7PkdpTpqX3sPqEnyN6aXc-gN7vJPAXE6zgNOxcLsnYzcxTdZNGqw"
    }

    resp_headers, content = http.request(uri, method=themethod, headers=headers)
    if resp_headers.status not in (200, 201, 204):
        helper.log_error('Failed to query api. url={}, HTTP Error={}, content={}'.format( uri, resp_headers.status, content))
    else:

        helper.log_info('Successfully queried url {}, content={}'.format(uri, content))
        return content
        
def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example sends rest requests to some endpoint
    # response is a response object in python requests library
    response = helper.send_http_request("http://www.splunk.com", "GET", parameters=None,
                                        payload=None, headers=None, cookies=None, verify=True, cert=None, timeout=None, use_proxy=True)
    # get the response headers
    r_headers = response.headers
    # get the response body as text
    r_text = response.text
    # get response body as json. If the body text is not a json string, raise a ValueError
    r_json = response.json()
    # get response cookies
    r_cookies = response.cookies
    # get redirect history
    historical_responses = response.history
    # get response status code
    r_status = response.status_code
    # check the response status, if the status is not sucessful, raise requests.HTTPError
    response.raise_for_status()


    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets the alert action parameters and prints them to the log
    album_id = helper.get_param("album_id")
    helper.log_info("album_id={}".format(album_id))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.log_info("Alert action spotifygettracks started.")

    # TODO: Implement your alert action logic here
    #query API Key alert action input
    album_id = helper.get_param("album_id") 
    
    #call the query URL REST Endpoint and pass the url and API token
    content = query_url(helper, album_id,'GET')  

    #write the response returned by Virus Total API to splunk index
    helper.addevent(content, sourcetype="VirusTotal")
    helper.writeevents(index="test_addon", host="localhost", source="VirusTotal")
    return 0
