# Burp Custom Deserializer
# Copyright (c) 2016, Marco Tinari
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from burp import IBurpExtender
from burp import IScannerInsertionPointProvider
from burp import IScannerInsertionPoint
from burp import IHttpListener
from burp import IParameter
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import ITab

from java.awt import BorderLayout, Component, GridLayout
from java.io import PrintWriter
from java.util import ArrayList
from java.util import List
from javax import swing
#~ from javax.swing import JScrollPane; #not necessary anymore
#~ from javax.swing import JSplitPane; #not necessary anymore
from javax.swing import JTabbedPane
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JTextField
from javax.swing import JCheckBox
from javax.swing import JRadioButton
from javax.swing import ButtonGroup
#~ from javax.swing import JTable;
#~ from javax.swing import SwingUtilities;
#~ from javax.swing.table import AbstractTableModel;


import sys
import binascii
import string
import re
from datetime import datetime

__VERSION__ = 1.1
EXTENSION_NAME = 'Custom Deserializer '+str(__VERSION__)
#~ DEBUG = True
DEBUG = False

EXTENSION_TABCAPTION = 'Deserializer'
MAGIC_PARAMETER = 'magic'
EXTENSION_EDITORTABCAPTION = 'Serialized parameter'
PARAMETERISPOST = True
PARAMETERISGET = False
PARAMETERISCOOKIE = False
URLENCODINGENABLED = False
BASE64ENCODINGENABLED = False
ASCII2HEXENCODINGENABLED = False
INTRUDERENABLED = False
SCANNERENABLED = False

#~ if DEBUG:
    #~ import pdb; pdb.set_trace()
    
# define your custom transformation functions here    
def convert_ascii2hex(asciidata):
    return ''.join([hex(ord(character))[2:].upper().zfill(2) for character in asciidata])
def convert_hex2ascii(hexdata):
    re.sub('[^0-9A-Fa-f]','',hexdata)
    return ''.join(chr(int(hexdata[i:i+2], 16)) for i in range(0, len(hexdata), 2))


class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory, ITab):
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
        global EXTENSION_NAME
        
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName(EXTENSION_NAME)
        
        # register ourselves as a Http Listener
        callbacks.registerHttpListener(self)

        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self) 
        
        # setup the UI
        self.initGui()        
        
        # add the custom tab to Burp's UI
        self._callbacks.addSuiteTab(self)  
        
        return
    #
    # create the Gui
    #    
    def initGui(self):
        #~ if DEBUG:
            #~ import pdb;
            #~ pdb.set_trace()
        tabPane = JTabbedPane(JTabbedPane.TOP)
        CreditsText = "<html># Burp Custom Deserializer<br/># Copyright (c) 2016, Marco Tinari<br/>#<br/># This program is free software: you can redistribute it and/or modify<br/># it under the terms of the GNU General Public License as published by<br/># the Free Software Foundation, either version 3 of the License, or<br/># (at your option) any later version.<br/>#<br/># This program is distributed in the hope that it will be useful,<br/># but WITHOUT ANY WARRANTY; without even the implied warranty of<br/># MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the<br/># GNU General Public License for more details.<br/>#<br/># You should have received a copy of the GNU General Public License<br/># along with this program.  If not, see <http://www.gnu.org/licenses/>.)<br/></html>"
        label1 = JLabel("<html>Usage:<br>1 - Select the desired encoding functions<br>2 - Enter the name of the parameter in the input field below and press the Apply button!</html>")
        label2 = JLabel(CreditsText)
        panel1 = JPanel()
        #set layout
        panel1.setLayout(GridLayout(11,1))
        panel2 = JPanel()
        panel1.add(label1)
        panel2.add(label2)
        tabPane.addTab("Configuration", panel1)
        tabPane.addTab("Credits", panel2)

        applyButton = JButton('Apply',actionPerformed=self.reloadConf)
        panel1.add(applyButton, BorderLayout.SOUTH)
        
        #define GET/POST/COOKIE radio button
        self.GETparameterTypeRadioButton = JRadioButton('GET parameter')
        self.POSTparameterTypeRadioButton = JRadioButton('POST parameter')
        self.COOKIEparameterTypeRadioButton = JRadioButton('COOKIE parameter')
        self.POSTparameterTypeRadioButton.setSelected(True)
        group = ButtonGroup()
        group.add(self.GETparameterTypeRadioButton)
        group.add(self.POSTparameterTypeRadioButton)
        group.add(self.COOKIEparameterTypeRadioButton)
        self.base64Enabled = JCheckBox("Base64 encode")
        self.URLEnabled = JCheckBox("URL encode")
        self.ASCII2HexEnabled = JCheckBox("ASCII to Hex")
        self.ScannerEnabled = JCheckBox("<html>Enable serialization in Burp Scanner<br>Usage:<br>1.Place unencoded values inside intruder request and define the placeholder positions<br>2.rightclick->Actively scan defined insertion points)</html>")
        self.IntruderEnabled = JCheckBox("<html>Enable serialization in Burp Intruder<br>Usage:<br>1.Place unencoded values inside intruder request and define the placeholder positions<br>2.Start the attack</html>")
        self.parameterName = JTextField("Parameter name goes here...",60)
        
        #set the tooltips
        self.parameterName.setToolTipText("Fill in the parameter name and apply")
        self.base64Enabled.setToolTipText("Enable base64 encoding/decoding")
        self.ASCII2HexEnabled.setToolTipText("Enable ASCII 2 Hex encoding/decoding") 
        self.URLEnabled.setToolTipText("Enable URL encoding/decoding")
        self.IntruderEnabled.setToolTipText("Check this if You want the extension to intercept and modify every request made by the Burp Intruder containing the selected paramter")
        self.ScannerEnabled.setToolTipText("Check this if You want the extension to intercept and modify every request made by the Burp Scanner containing the selected paramter")

        #add checkboxes to the panel            
        panel1.add(self.parameterName)
        panel1.add(self.POSTparameterTypeRadioButton)
        panel1.add(self.GETparameterTypeRadioButton)
        panel1.add(self.COOKIEparameterTypeRadioButton)
        panel1.add(self.base64Enabled)
        panel1.add(self.URLEnabled)
        panel1.add(self.ASCII2HexEnabled)
        panel1.add(self.IntruderEnabled)
        panel1.add(self.ScannerEnabled)
        #assign tabPane
        self.tab = tabPane
        
    def reloadConf(self,event):
        #~ if DEBUG:
            #~ import pdb; pdb.set_trace()
        source = event.getSource()
        print 'APPLY button clicked. New configuration loaded.'
        global MAGIC_PARAMETER
        global PARAMETERISPOST
        global PARAMETERISGET
        global PARAMETERISCOOKIE
        global BASE64ENCODINGENABLED
        global ASCII2HEXENCODINGENABLED
        global URLENCODINGENABLED
        global INTRUDERENABLED
        global SCANNERENABLED
        MAGIC_PARAMETER=self.parameterName.getText()
        print 'Base64 checkbox is: '+str(self.base64Enabled.isSelected())
        if self.base64Enabled.isSelected(): 
            BASE64ENCODINGENABLED=True
        else:
            BASE64ENCODINGENABLED=False
        print 'ASCII2Hex checkbox is: '+str(self.ASCII2HexEnabled.isSelected())
        if self.ASCII2HexEnabled.isSelected(): 
            ASCII2HEXENCODINGENABLED=True
        else:
            ASCII2HEXENCODINGENABLED=False
        print 'URL checkbox is: '+str(self.URLEnabled.isSelected())
        if self.URLEnabled.isSelected(): 
            URLENCODINGENABLED=True
        else:
            URLENCODINGENABLED=False
        print 'New Magic parameter is: '+str(MAGIC_PARAMETER)
        if self.POSTparameterTypeRadioButton.isSelected(): #BODYPARAM
            PARAMETERISPOST=True
            print "parameterispost has been set to: " + str(PARAMETERISPOST)
        else:
            PARAMETERISPOST=False
            print "parameterispost has been set to: " + str(PARAMETERISPOST)
        if self.GETparameterTypeRadioButton.isSelected(): #GETPARAM
            PARAMETERISGET=True
            print "parameterisget has been set to: " + str(PARAMETERISGET)
        else:
            PARAMETERISGET=False
            print "parameterisget has been set to: " + str(PARAMETERISGET)
        if self.COOKIEparameterTypeRadioButton.isSelected(): #COOKIEPARAM
            PARAMETERISCOOKIE=True
            print "parameteriscookie has been set to: " + str(PARAMETERISCOOKIE)
        else:
            PARAMETERISCOOKIE=False
            print "parameteriscookie has been set to: " + str(PARAMETERISCOOKIE)
        if self.ScannerEnabled.isSelected(): 
            SCANNERENABLED=True
            print "Scanner Enabled"
        else:
            SCANNERENABLED=False
        if self.IntruderEnabled.isSelected(): 
            INTRUDERENABLED=True
            print "Intruder Enabled"
        else:
            INTRUDERENABLED=False
    #
    # implement IHTTPListener
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        global PARAMETERISPOST
        global PARAMETERISGET
        global PARAMETERISCOOKIE
        global URLENCODINGENABLED
        global BASE64ENCODINGENABLED
        global ASCII2HEXENCODINGENABLED
        global INTRUDERENABLED
        global SCANNERENABLED
        #only process requests
        if not messageIsRequest:
            return
        #only process messages from Intruder and Scanner, otherwise exit
        #if (not self._callbacks.TOOL_INTRUDER == toolFlag):
        if ((not ((self._callbacks.TOOL_INTRUDER == toolFlag) and INTRUDERENABLED)) and (not ((self._callbacks.TOOL_SCANNER == toolFlag) and SCANNERENABLED))):
            #print "exiting- toolflag:"+str(toolFlag)+' INTRUDERENABLED='+str(INTRUDERENABLED)+' SCANNERENABLED='+str(SCANNERENABLED)
            return
        #if ((not self._callbacks.TOOL_INTRUDER == toolFlag)) and ((not self._callbacks.TOOL_SCANNER == toolFlag)):#remove the comment to always enable
        if DEBUG:
            print "IHTTPListener Enabled in: " + str(toolFlag)
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        timestamp = datetime.now()
        if DEBUG: 
            print "Intercepting message at: ", timestamp.isoformat()
        #parameters = requestInfo.getParameters()
        dataParameter = self._helpers.getRequestParameter(currentRequest.getRequest(), MAGIC_PARAMETER)
        #FIXME: add exception handling for multiple parameters with the same name and/or in a different position!!!
        if DEBUG:
            print 'dataparameter:'+str(dataParameter)
        if (dataParameter == None):
            if DEBUG:
                print 'Parameter does not exist'
            return
        serializedValue = dataParameter.getValue()
        #FIXME: substitute '[AND]' placeholder with '&' charachter - we should do something more elegant here :/
        serializedValue = re.sub(r'\[AND\]', '&', serializedValue) 
        print "unserialized parameter value: ", str(serializedValue)
        if BASE64ENCODINGENABLED: #if base64Encode is selected
            serializedValue = self._helpers.base64Encode(serializedValue)
            if DEBUG:
                print "base64 encoded parameter value: ", str(serializedValue)
        if URLENCODINGENABLED: #if URLEncode is selected
            serializedValue = self._helpers.urlEncode(serializedValue)
            if DEBUG:
                print "URL ecoded parameter value: ", str(serializedValue)
        if ASCII2HEXENCODINGENABLED: #if ASCII2HexEncode is selected
            serializedValue = convert_ascii2hex(serializedValue)
            if DEBUG:
                print "ASCII2Hex ecoded parameter value: ", str(serializedValue)
        print "serialized parameter value: ", serializedValue
        if PARAMETERISPOST:
            if DEBUG:
                print "parameter is BODY"
            currentRequest.setRequest(self._helpers.updateParameter(currentRequest.getRequest(),self._helpers.buildParameter(MAGIC_PARAMETER, serializedValue,IParameter.PARAM_BODY)))
        elif PARAMETERISGET:
            if DEBUG:
                print "parameter is in URL"
            currentRequest.setRequest(self._helpers.updateParameter(currentRequest.getRequest(),self._helpers.buildParameter(MAGIC_PARAMETER, serializedValue,IParameter.PARAM_URL)))       
        elif PARAMETERISCOOKIE:
            if DEBUG:
                print "parameter is a COOKIE"
            currentRequest.setRequest(self._helpers.updateParameter(currentRequest.getRequest(),self._helpers.buildParameter(MAGIC_PARAMETER, serializedValue,IParameter.PARAM_COOKIE)))       
        return
    
    # 
    # implement ITab
    #
    
    def getTabCaption(self):
        global EXTENSION_TABCAPTION
        return(EXTENSION_TABCAPTION)

    def getUiComponent(self):
        #~ return self._splitpane
        return self.tab


    # 
    # implement IMessageEditorTabFactory
    #
    def createNewInstance(self, controller, editable):
        
        # create a new instance of our custom editor tab
        return CustomInputTab(self, controller, editable)
        
# 
# class implementing IMessageEditorTab
#

class CustomInputTab(IMessageEditorTab):

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        
        # create an instance of Burp's text editor, to display our deserialized MAGIC_PARAMETER
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        return
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        global EXTENSION_EDITORTABCAPTION
        return EXTENSION_EDITORTABCAPTION
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # enable this tab for requests containing a MAGIC_PARAMETER parameter
        return isRequest and not self._extender._helpers.getRequestParameter(content, MAGIC_PARAMETER) is None
        
    def setMessage(self, content, isRequest):
        global URLENCODINGENABLED
        global BASE64ENCODINGENABLED
        global ASCII2HEXENCODINGENABLED
        if (content is None):
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            # retrieve the MAGIC_PARAMETER parameter
            # FIXME: doed not get the correct parameter when the same parameter name is used both in BODY and URL
            parameter = self._extender._helpers.getRequestParameter(content, MAGIC_PARAMETER)
            parametervalue = parameter.getValue()
            # deserialize the MAGIC_PARAMETER value            
            if URLENCODINGENABLED: #URLencoded
                parametervalue = self._extender._helpers.urlDecode(parametervalue)
                if DEBUG:
                    print "URLENCODEENABLED True - setmessage : "+parametervalue
            if BASE64ENCODINGENABLED: #Base64encoded
                parametervalue = self._extender._helpers.base64Decode(parametervalue)
                if DEBUG:
                    print "BASE64ENCODINGENABLED True - setmessage : "+parametervalue
            if ASCII2HEXENCODINGENABLED: #ASCII2Hexencoded
                parametervalue = convert_hex2ascii(parametervalue)
                if DEBUG:
                    print "ASCII2HEXENCODINGENABLED True - setmessage : "+parametervalue
            #self._txtInput.setText(self._extender._helpers.base64Decode(self._extender._helpers.urlDecode(parameter.getValue())))
            self._txtInput.setText(parametervalue)
            self._txtInput.setEditable(self._editable)
        # remember the displayed content
        self._currentMessage = content
        return
    
    def getMessage(self):
        #~ if DEBUG:
            #~ import pdb; pdb.set_trace()
        global ASCII2HEXENCODINGENABLED
        global BASE64ENCODINGENABLED
        global URLENCODINGENABLED
        # determine whether the user modified the deserialized data
        if (self._txtInput.isTextModified()):
            # reserialize the data
            text = self._extender._helpers.bytesToString(self._txtInput.getText())
            if ASCII2HEXENCODINGENABLED: #ASCII2Hexencoded
                #string = self._extender._helpers.bytesToString(text)
                text = convert_ascii2hex(text)
                if DEBUG:
                    print "ASCII2HEXENCODINGENABLED True - getmessage : "+text
            if BASE64ENCODINGENABLED: #Base64encoded
                text = self._extender._helpers.base64Encode(text)
                if DEBUG:
                    print "BASE64ENCODINGENABLED True - getmessage : "+str(text)
            if URLENCODINGENABLED: #URLencoded
                #string = self._extender._helpers.bytesToString(text)
                text = self._extender._helpers.urlEncode(text)               
                if DEBUG:
                    print "URLENCODEENABLED True - getmessage: "+text
            #input = self._extender._helpers.urlEncode(self._extender._helpers.base64Encode(text))
            #input=text
            # update the request with the new parameter value
            #fix the parameter type selection
            if PARAMETERISPOST:
                if DEBUG:
                    print "parameter is in BODY"
                    print "parameterispost = " + str(PARAMETERISPOST)
                return self._extender._helpers.updateParameter(self._currentMessage, self._extender._helpers.buildParameter(MAGIC_PARAMETER, text, IParameter.PARAM_BODY))
            elif PARAMETERISGET:
                if DEBUG:
                    print "parameter is in URL"
                    print "parameterisget = " + str(PARAMETERISGET)
                return self._extender._helpers.updateParameter(self._currentMessage, self._extender._helpers.buildParameter(MAGIC_PARAMETER, text, IParameter.PARAM_URL))
            else:
                if DEBUG:
                    print "parameter is in COOKIE"
                    print "parameteriscookie = " + str(PARAMETERISCOOKIE)
                return self._extender._helpers.updateParameter(self._currentMessage, self._extender._helpers.buildParameter(MAGIC_PARAMETER, text, IParameter.PARAM_COOKIE))
        else:
            return self._currentMessage

    def isModified(self):
        
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        
        return self._txtInput.getSelectedText()       	
