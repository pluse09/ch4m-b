import sys
import re

from java.io import PrintWriter
from burp import IBurpExtender, ISessionHandlingAction


# Modify
regex = r'XXXX'
headerName = "XXXX"

class BurpExtender(IBurpExtender, ISessionHandlingAction):

    def getActionName(self):
        return 'Custom Header For Macro - Body'

    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('Custom Header For Macro - Body')

        callbacks.registerSessionHandlingAction(self)

        sys.stdout = callbacks.getStdout()

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStdout(), True)

        self.stdout.println('Custom Header For Macro - Body: Loaded.')

        self.callbacks = callbacks

        self.helpers = callbacks.getHelpers()

    def performAction(self, currentRequest, macroItems):
        if not macroItems or len(macroItems) == 0:
            self.stdout.println("No macro items available.")
            return
        
        lastMacroResponse = macroItems[-1].getResponse()
        if lastMacroResponse is None:
            self.stdout.println("No response found in the macro.")
            return
        
        extractedToken = self._extract_token_from_response(lastMacroResponse)
        if extractedToken is None:
            self.stdout.println("No token found in the response body.")
            return

	    # Modify
        self._inject_header_into_request(currentRequest, headerName, "Bearer {}".format(extractedToken))
        

    def _extract_token_from_response(self, response):
        analyzedResponse = self.helpers.analyzeResponse(response)
        bodyOffset = analyzedResponse.getBodyOffset()

        responseBody = response[bodyOffset:]
        responseBodyStr = self.helpers.bytesToString(responseBody)

        match = re.search(regex, responseBodyStr)
        if not match:
            self.stdout.println("No token found in response body.")
            return None
        return match.group(1)
    
    def _inject_header_into_request(self, currentRequest, headerName, headerValue):
        originalRequest = currentRequest.getRequest()
        analyzedRequest = self.helpers.analyzeRequest(originalRequest)
        headers = list(analyzedRequest.getHeaders())

        header_found = False
        for i, header in enumerate(headers):
            if header.lower().startswith("{}:".format(headerName.lower())):
                headers[i] = "{}: {}".format(headerName, headerValue)
                header_found = True
                break
        if not header_found:
            headers.append("{}: {}".format(headerName, headerValue))

        body = originalRequest[analyzedRequest.getBodyOffset():]
        updatedRequest = self.helpers.buildHttpMessage(headers, body)

        currentRequest.setRequest(updatedRequest)
        self.stdout.println("Injected Header: {}: {}".format(headerName, headerValue))
