#Introduction
What to do when Burp does not handle custom serialization implemented by specific applications, or any other data format that Burp does not natively support?

You might have found Yourself manually decoding->editing->encoding the payloads in the intruder and repeater tabs, haven't you?

This extension helps us with this time consuming task.... and eventually automates most of it.


# Custom deserializer
Custom Deserializer is an extension for [Burp Suite](https://portswigger.net/burp/). 

It is designed to help security testers by speeding up manual testing of (web)application and extend the Burp Scanner and Burp Intruder automated test capabilities.
The extension is partially based on the Sample Burp Suite extension: custom editor tab http://blog.portswigger.net/2012/12/sample-burp-suite-extension-custom_17.html

The extension is now available via the [BApp Store](https://portswigger.net/bappstore/)

# Author
- Marco Tinari

# Installation 
1.	Set up Burp Suite Jython standalone JAR 
2.	Download and load CustomDeserializer.py
3.	Set up the extension from the Deserializer tab


# Set up guide - editor tab
1. Click on the Deserializer tab
2. Enter the name of the parameter You want to deal with
3. Set the parameter position: POST for body, GET for URL and COOKIE for Cookie header
4. Select the transformation function to be applied. 
  * When selected, the functions will be applied as follows
  * deserialized data -> ASCII2HEX() -> Base64decode() -> URLdecode() -> serialized data
  * Serialized data -> URLdecode() -> Base64decode() ->  ASCII2HEX() -> deserialized data
5. Click on the *small* Apply button

![Image of the plugin](https://raw.githubusercontent.com/marcotinari/CustomDeserializer/master/CustomDeserializer-full-screen.png)


# Set up guide - Intruder integration
1. enable the Intruder integration in the Deserializer tab
2. send the Request to the Intruder tab
3. replace the encoded parameter value with the decoded value 
4. define the Intruder insertion points with placeholder
  * Example - ASCII2HEX encoded parameter: 
    * encoded value:					``variable2=757365723d41646d696e7c70617373776f72643d736563726574``
    * decoded value:					``variable2=user=Admin|password=secret``
    * valid value to use in the intruder tab:	``variable2=user=§Admin§|password=§secret§``
  * It is important to replace every occurence of ampersands '&' within the decoded value  with the charachters combination '\[AND\]'.
  * Example - base64 and URL encoded parameter: 
    * encoded value: ``variable1=UGFyYW1ldGVyMT0xMjM0JlBhcmFtZXRlcjI9QUJDRA==``
    * decoded value: ``variable1=Parameter1=1234&Parameter2=ABCD``
    * valid value to use in the intruder tab: ``variable1=Parameter1=§1234§[AND]Parameter2=§ABCD§``

5. start the Intruder attack
6. the parameter values will be automatically encoded according to the selected transformation functions
7. TIP: In the Intruder attack result/history You will find the decoded version of the payload. Use an external Extension (e.g. Logger++ is a great extension from Soroush Dalili, NCC Group) if You want to check the actual HTTP Request after being transformed by the extension 

# Set up guide - Scanner integration
1. enable the Intruder integration in the Deserializer tab
2. send the Request to the Intruder tab
3. replace the encoded parameter value with the decoded value (check Intruder integration instruction for examples) 
4. set the insertion points with the placeholders
5. right click -> Actively scan defined insertion point 
6. while scanning, the parameter values will be automatically ancoded according to the selected transformation functions
7. TIP: In the Scanner finding issues HTTP Requests You will find the decoded version of the payload used. Use an external Extension (e.g. Logger++ is a great extension from Soroush Dalili, NCC Group) if You want to check the actual HTTP Request after being transformed by the extension 

# Extension demo How-To
[Using the extension demo](https://youtu.be/jdUOLoqCFL8)
