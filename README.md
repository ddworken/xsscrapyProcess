# xsscrapyProcess
A python script to help process the output from xsscrapy and remove duplicate vulnerabilities

```
usage: xsscrapyProcess.py fileName
                          [--removeURLs REMOVEURLS]
                          [--onlyURLs ONLYURLS]
                          [--removeDuplicateInjections]
                          [--removeUserAgentVulns]
                          [--output OUTPUT]
                          [--quiet]
```

###Examples:
=========

Read input from xsscrapy-vulns.txt and remove all URLs containing ```example.com/blog/```

```
python xsscrapyProcess.py xsscrapy-vulns.txt --removeURLs example.com/blog/
```
==========
Read input from xsscrapy-vulns.txt and remove all URLs that don't contain ```example.com/blog/```

```
python xsscrapyProcess.py xsscrapy-vulns.txt --onlyURLs example.com/blog/
```
==========
Read input from xsscrapy-vulns.txt and remove vulnerabilities with duplicate injection points. 

```
python xsscrapyProcess.py xsscrapy-vulns.txt --removeDuplicateInjections
```
==========
Read input from xsscrapy-vulns.txt and remove user agent based vulnerabilities..

```
python xsscrapyProcess.py xsscrapy-vulns.txt --removeUserAgentVulns
```
