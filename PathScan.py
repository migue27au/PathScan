#!/usr/bin/python3

# Author: Migue27au --> https://github.com/migue27au
#
# Pententesing script
# This script make path finding of a url based of a dictionary file

import numpy as np
import pandas as pd
import concurrent.futures
import requests
import sys, getopt, time
from datetime import datetime

HTTP_OK = 200
HTTP_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH']
findings = []

LOGO = '                                                                \r\n      /////   ////  ////// //  //   //////  ////   ////  //  // \r\n     //  // //  //   //   //  //   //  // //  // //  // /// //  \r\n    /////  //////   //   //////    ///   //     ////// /// //   \r\n   //     //  //   //   //////      /// //     //  // // ///    \r\n  //     //  //   //   //  //   //  // //  // //  // // ///     \r\n //     //  //   //   //  //   //////  ////  //  // //  //      \r\n                                                                \r\n                                                                                     \r\n    - By Migue27au --> https://github.com/migue27au             \r\n    - Version: 1.0 \r\n'
timeout = 2
urlRequests = []

def main(argv):
    verbose = False
    maxConnections = 100
    url = ''
    paths = None
    extensions = None
    ofile = None
    statusCodes = []
    threadsNum = 100
    methods = [HTTP_METHODS[0]]
    port = 0

    print(LOGO)

    

    if len(argv) < 1:
        usage(1)

    try:
        options, args = getopt.getopt(argv,"hu:d:o:vt:m:p:s:e:",["help","url=","paths=", "ofile=","timeout=", "method=","port=", "max_connections=", "status_codes=", "extensions="])
    except getopt.GetoptError as e:
        print(e)
        usage(2)
        
    
    
    
    if len(options) < 1:
        usage(3)

    for o,a in options:
        if o == "-v":
            verbose = True
        elif o in ("-h", "--help"):
            usage(0)
        elif o in ("-u", "--url"):
            url = a
        elif o in ("-d", "--paths"):
            try:
                paths = open(a, "r")
            except FileNotFoundError:
                usage(3)
        elif o in ("-e", "--extensions"):
            try:
                extensions = open(a, "r").readlines()
            except FileNotFoundError:
                usage(3)
        elif o in ("-o", "--ofile"):
            try:
                ofile = open(a, "w")
            except FileNotFoundError:
                usage(3)
        elif o in ("-p","--port"):
            try:
                port = int(a)
                if port < 0 or port > 65535:
                    usage(8)
            except:
                usage(8)
        elif o in ("-t","--timeout"):
            try:
                timeout = int(a)
                if timeout < 0:
                    usage(8)
            except:
                usage(8)
        elif o in ("-m", "--method"):
            for i in range(len(HTTP_METHODS)):
                try:
                    if a[i] == '1' and i > 0:
                        methods.append(HTTP_METHODS[i])
                    elif a[i] == '0':
                        methods.remove(HTTP_METHODS[i])
                except (IndexError, ValueError):
                    print('')
        elif o in ("-s", "--status_codes"):
            statusCodes = a.split(',')
            try:
                statusCodes = [int(i, base=10) for i in statusCodes]
            except:
                usage(8)
        elif o in ("--max_connections"):
            try:
                maxConnections = int(a)
            except:
                usage(8)
        else:
            usage(2)


    #check url
    if url == '':
        usage(4)

    count = 0
    for i in url: 
        if i == '/': 
            count = count + 1
    
    if count < 3:
        usage(10)
    
    #check schema
    if url.find("https://") == -1 and url.find("http://") == -1:
        usage(5)

    #set default port if not specified
    if port == 0:
        if url.find("https://") != -1:
            port = 443
        elif url.find("http://") != -1:
            port = 80    


    if paths == None:
        for method in methods:
            urlSplitted = url.split('/',4)
            urlRequests.append([urlSplitted[0]+'//'+urlSplitted[2]+':'+str(port)+'/'+urlSplitted[3], method])
    else:
        for line in paths:
            for method in methods:
                urlSplitted = url.split('/',4)
                r = [urlSplitted[0]+'//'+urlSplitted[2]+':'+str(port)+'/'+line.rstrip(), method]
                urlRequests.append(r)
                if verbose == True:
                    print(r)
    
    if not extensions == None:
        urlRequestsAux = urlRequests
        for i in range(len(urlRequests)):
            for extension in extensions:
                path = urlRequestsAux[i][0]+extension.rstrip('\n')
                if verbose == True:
                    print(path)
                urlRequests.append([path,urlRequestsAux[i][1]])
                    

    if verbose == True:
        print(urlRequests)

    #Thanks to Glen Thompson (https://stackoverflow.com/users/3866246/glen-thompson) for his contributions on stackoverflow that let me complete this part
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=maxConnections) as executor:
            future_to_url = (executor.submit(connect, urlRequest) for urlRequest in urlRequests)
            time1 = time.time()
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    response = future.result()
                except Exception as exc:
                    print(exc)
                finally:
                    if len(statusCodes) > 0:
                        if response[1] in statusCodes:
                            findings.append(response)
                    else:
                        findings.append(response)

                    totalComplete = "{:.2f}".format(100*(len(findings)/len(urlRequests)))
                    print(str(totalComplete) + '%', end='\r')

            time2 = time.time()
            print(f'Took {time2-time1:.2f} s')
            df = pd.DataFrame(findings, columns=["url", "method", "code"])

            print(df)

            if not ofile == None:
                now = datetime.now()
                s = "PathScan | " + str(now) + ' | Scan took: ' + str(time2-time1) + 's\r\n'
                ofile.write(s)
                ofile.write(df.to_string())
                ofile.close()
    except KeyboardInterrupt:
        print('\nScan cancel by user.')
 

def connect(params):
    url = params[0]
    method = params[1]
    response = None
    try:
        if(method == HTTP_METHODS[0]):
            response = requests.get(url, timeout=timeout)
        elif(method == HTTP_METHODS[1]):
            response = requests.post(url, timeout=timeout)
        elif(method == HTTP_METHODS[2]):
            response = requests.head(url, timeout=timeout)
        elif(method == HTTP_METHODS[3]):
            response = requests.options(url, timeout=timeout)
        elif(method == HTTP_METHODS[4]):
            response = requests.put(url, timeout=timeout)
        elif(method == HTTP_METHODS[5]):
            response = requests.delete(url, timeout=timeout)
        elif(method == HTTP_METHODS[6]):
            response = requests.trace(url, timeout=timeout)
        return url, method, response.status_code
    except Exception as e:
        #print(e)
        return url, method, "error"

def showHelp():
    print("Usage:python3 pathscan.py -u <url (schema and resource '/' is required) [Options]")
    print("Examples:")
    print(" - python3 pathscan.py -u https://www.google.com -d d.txt -m 110001 -s 200,201")
    print("\tperform a GET, POST, and PATCH using the dictionary d.txt to\n\thttps://www.google.com and must show responses with status code 200 and 201.")
    print(" - python3 pathscan.py -u https://www.google.com -d d.txt -e e.txt -o save.txt")
    print("\tperform a scan using the dictionary d.txt and extensions e.txt. Finally\n\tsave the output in the file save.txt.")
    print("Options")
    print("  -h: show this help.")
    print("  -u <url>: set the url, IP address or domain to attack. Require schema (http://\n\tor https://) and resource: '/'. Example --> https://www.google.es/.")
    print("  -d/--paths <file>: wich dictionary must be used to perfom the attack.")
    print("  -e/--extensions <file>: extensions dictionary to apply to the end of each path.")
    print("  -o/--ofile <file>: save the output to the given filename.")
    print("  -m/--methods <binary_number>: select the HTTP methods of the scan. Available\n\tmethods are GET, POST, HEAD, OPTIONS, PUT, DELETE, and PATCH. Default is GET.")
    print("  -s/--status_codes <number>: wich response status codes should be return in\n\tthe output. Several status codes must be separated by commas.")
    print("  -p/--port <number>: indicate the port where the target host is listening.")
    print("  -v:  verbosed mode.")
    print("  -t/--timeout <number>: set the timeout of every packet. Default value is 2s.")
    print("  --max_connections <number>: set the number of simultaneous connections. Big\n\tvalues may cause firewall block. Default value is 100.")


def usage(option):
    helpString = ''
    if option == 0:
        showHelp()
        sys.exit(1)
    elif option == 1:
        helpString = 'Insuficient arguments. Use python PathScan.py -h to deploy help.'
    elif option == 2:
        helpString = 'Option not recognised. Use python PathScan.py -h to deploy help.'
    elif option == 3:
        helpString = 'File not found or doesn\'t exists'
    elif option == 4:
        helpString = 'Url not specified'
    elif option == 5:
        helpString = 'Schema not suplied. Include http:// or https://'
    elif option == 6:
        helpString = 'Cannot connect to host.'
    elif option == 7:
        helpString = 'Lost connection.'
    elif option == 8:
        helpString = 'Wrong argument.'
    elif option == 10:
        helpString = 'You must specified the last \'/\' in the url. Example -> https://www.google.com/'
    print(helpString)
    sys.exit(1)


if __name__ == "__main__":
   main(sys.argv[1:])