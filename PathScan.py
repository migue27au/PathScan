#!/usr/bin/python3

# Author: Migue27au --> https://github.com/migue27au
#
# Pententesing script
# This script make path finding of a url based of a dictionary file


import pandas as pd
import concurrent.futures
import requests
import sys, getopt, time
from datetime import datetime

HTTP_OK = 200
HTTP_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'PATCH']
findings = []

LOGO = '                                                                \r\n      /////   ////  ////// //  //   //////  ////   ////  //  // \r\n     //  // //  //   //   //  //   //  // //  // //  // /// //  \r\n    /////  //////   //   //////    ///   //     ////// /// //   \r\n   //     //  //   //   //////      /// //     //  // // ///    \r\n  //     //  //   //   //  //   //  // //  // //  // // ///     \r\n //     //  //   //   //  //   //////  ////  //  // //  //      \r\n                                                                \r\n                                                                                     \r\n    - By Migue27au --> https://github.com/migue27au             \r\n                                                                \r\n'
timeout = 2
urlRequests = []
verbose = False


def main(argv):
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
                extensions = open(a, "r")
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
            if extensions == None:
                urlSplitted = url.split('/',4)
                urlRequests.append([urlSplitted[0]+'//'+urlSplitted[2]+':'+str(port)+'/'+urlSplitted[3], method])
            else:
                for extension in extensions:
                    urlSplitted = url.split('/',4)
                    urlRequests.append([urlSplitted[0]+'//'+urlSplitted[2]+':'+str(port)+'/'+urlSplitted[3]+extension.rstrip(), method])
    else:
        for line in paths:
            for method in methods:
                if(extensions == None):
                    urlRequests.append([url+':'+str(port)+'/'+line.rstrip(), method])
                else:
                    for extension in extensions:
                        urlRequests.append([url+':'+str(port)+'/'+line.rstrip()+extension.rstrip(), method])

    #Thanks to Glen Thompson (https://stackoverflow.com/users/3866246/glen-thompson) for his contributions on stackoverflow that let me complete this part
    with concurrent.futures.ThreadPoolExecutor(max_workers=maxConnections) as executor:
        future_to_url = (executor.submit(connect, urlRequest) for urlRequest in urlRequests)
        time1 = time.time()
        for future in concurrent.futures.as_completed(future_to_url):
            try:
                response = future.result()
            except Exception as exc:
                response = str(type(exc))
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
        df = pd.DataFrame(findings, columns=["url", "code", "method"])

        print(df)

        if not ofile == None:
            now = datetime.now()
            s = "PathScan | " + str(now) + ' | Scan took: ' + str(time2-time1) + 's\r\n'
            ofile.write(s)
            ofile.write(df.to_string())
            ofile.close()
 

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
        return url, response.status_code, method
    except Exception as e:
        print(e)
        return url, "error"

def usage(option):
    helpString = ''
    if option == 0:
        helpString = 'Help \n 1 \n 2'
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
    print(helpString)
    sys.exit(1)


if __name__ == "__main__":
   main(sys.argv[1:])