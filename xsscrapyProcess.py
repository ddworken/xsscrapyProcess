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
    return lines

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File name to parse")
    parser.add_argument("--removeURLs", help="Remove URLs containing a string")
    parser.add_argument("--onlyURLs", help="Only display URLs containing a string")
    args = parser.parse_args()
    data = readFileToArray(args.file)
    if args.removeURLs:
        data = removeURLsContainingString(data, args.removeURLs)
    if args.onlyURLs:
        data = removeURLsNotContainingString(data, args.onlyURLs)
    for line in exportToOriginalFormat(data):
        print line
david@localhost /home/david $ 
