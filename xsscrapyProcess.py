#!/bin/python

import argparse

def readFileToArray(filePath):
    data=[]
    tempArr = []
    dataTypes = ['URL','response URL','Unfiltered','Payload','Type','Injection point','Possible payloads','Line']
    with open(filePath) as file:
        lines = file.read().splitlines()
    for index,line in enumerate(lines):
        if line.startswith(dataTypes[0]):
            data.append(tempArr)
            tempArr = []
        tempDict = {}
        for dataType in dataTypes:
            if line.startswith(dataType):
                tempDict[line.split(':',1)[0]] = line.split(':',1)[1][1:]   #Max split once to deal with http://
                tempArr.append(tempDict)
    return data
    #Data is an array of arrays containing dicts. E.g.
    #[
    #   [
    #       {'URL':'http://example.com'},
    #       {'response URL':'http://example.com'},
    #       {'Unfiltered': '(){}<x>:'},
    #       {'Payload': '1zqjwk\'"(){}<x>:1zqjwk;9'},
    #       {'Type': 'url'},
    #       {'Injection point': 'end of url'},
    #       {'Possible payloads': '<svG onLoad=prompt(9)>'},
    #       {'Line': '<a href=example.com>'}
    #   ],
    #   [
    #       {'URL':'http://example.com'},
    #       {'response URL':'http://example.com'},
    #       {'Unfiltered': '(){}<x>:'},
    #       {'Payload': '1zqjwk\'"(){}<x>:1zqjwk;9'},
    #       {'Type': 'url'},
    #       {'Injection point': 'end of url'},
    #       {'Possible payloads': '<svG onLoad=prompt(9)>'},
    #       {'Line': '<a href=example.com>'}
    #   ]
    #]

def removeURLsContainingString(data, string):
    newData = []
    for vulnArr in data:
        try:
            respURL = vulnArr[1]['response URL']
            if not string in respURL:
                newData.append(vulnArr)
        except:
            pass
    return newData

def removeURLsNotContainingString(data, string):
    newData = []
    for vulnArr in data:
        try:
            respURL = vulnArr[1]['response URL']
            if string in respURL:
                newData.append(vulnArr)
        except:
            pass
    return newData

def exportToOriginalFormat(data):
    lines = []
    for vulnArr in data:
        for dict in vulnArr:
            lines.append([': '.join((d, str(dict[d]))) for d in sorted(dict, key=dict.get, reverse=True)][0])
        lines.append('')
    return lines

def removeDuplicateInjectionPoints(data):
    newData = []
    found = []
    foundEndURL = []
    foundURLPath = []
    for vulnArr in data:
        try:
            injPoint = vulnArr[5]['Injection point']
            if 'end of url' not in injPoint and 'URL path' not in injPoint:
                if injPoint not in found:
                    found.append(injPoint)
                    newData.append(vulnArr)
            else:                                   #Better heuristics needed for duplicate URLs (Levenshtein?)
                url = vulnArr[1]['response URL']
                if 'end of url' in injPoint:
                    if url not in foundEndURL:
                        foundEndURL.append(url)
                        newData.append(vulnArr)
                if 'URL path' in injPoint:
                    if url not in foundURLPath:
                        foundURLPath.append(url)
                        newData.append(vulnArr)
        except:
            pass
    return newData

def removeUserAgentVulns(data):
    newData = []
    for vulnArr in data:
        try:
            injPoint = vulnArr[5]['Injection point']
            if 'Referer' not in injPoint:
                newData.append(vulnArr)
        except:
            pass
    return newData

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File name to parse")
    parser.add_argument("--removeURLs", help="Remove URLs containing a string")
    parser.add_argument("--onlyURLs", help="Only display URLs containing a string")
    parser.add_argument("--removeDuplicateInjections", help="Automatically removes duplicate injection points", action='store_true')
    parser.add_argument("--removeUserAgentVulns", help="Automatically removes vulnerabilities based on injecting into the user agent field. ", action='store_true')
    parser.add_argument("--output", help="Specifies an output file for the new vulnerabilities")
    parser.add_argument("--quiet", help="Silences the program", action='store_true')
    args = parser.parse_args()
    data = readFileToArray(args.file)
    if args.removeURLs:
        data = removeURLsContainingString(data, args.removeURLs)
    if args.onlyURLs:
        data = removeURLsNotContainingString(data, args.onlyURLs)
    if args.removeDuplicateInjections:
        data = removeDuplicateInjectionPoints(data)
    if args.removeUserAgentVulns:
        data = removeDuplicateInjectionPoints(data)
    if args.output:
        outputFile=open(args.output, 'w+')
        for line in exportToOriginalFormat(data):
            outputFile.write(line + '\n')
    if not args.quiet:
        for line in exportToOriginalFormat(data):
            print line
