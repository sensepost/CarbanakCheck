#!/usr/env/python
# [glenn|adam@sensepost.com]

import os.path
import urllib
import argparse

print "-=[ Carbanak log scanner // @sensepost ]=- "
print "This script will look at HTTP GET requests in web logs and look for the presence of English words. The absence of this may indicate Carbanak, as all requests are Base64 encoded and RC2 encrypted.\n"

parser = argparse.ArgumentParser(description='Check logs for presence of Carbanak')
parser.add_argument('--logfile', dest="logfile", required=True,
    help="Supply log file to examine", metavar="FILE")
parser.add_argument('--wordlength', dest="wordlengths", nargs='+', type=int, required=False, default=[4,5])

args = parser.parse_args()

wordsDict = {}


words = "http://www-01.sil.org/linguistics/wordlists/english/wordlist/wordsEn.txt"

if not os.path.isfile("wordsEn.txt"):
  print "[+] Downloading English word list..."
  urllib.urlretrieve(words, "wordsEn.txt")
  print "     Download complete.."

with open('wordsEn.txt') as f:
    for word in f:
        word = word.rstrip()
        wlen = len(word)
        if wlen in args.wordlengths:
            if not wordsDict.get(wlen):
                wordsDict[wlen] = [word]
            else:
                wordsDict[wlen].append(word)
total = 0
for wlens, words in wordsDict.iteritems():
    total += len(words)

print " [+] Checking %d English words of lengths %s against log file '%s'..." % (total, args.wordlengths, args.logfile)

badLines = []
lnum = []

l = 0
with open(args.logfile) as f:
    for line in f:
        badLine = True
        if "GET" in line:
            get = "/".join(line.split()[6].split("/")[3:]) #Retrieve the path. Such ugly code. Amaze.
        for wlen, words in wordsDict.iteritems():
            for word in words:
                if word in get:
                    badLine = False
        if badLine:
            badLines.append(line)
            lnum.append(l)
        l+=1

print " [+] %d suspicious GET requests found in log file:" % len(badLines)
for idx, val in enumerate(badLines):
    print "     Line %d: %s" % (lnum[idx]+1, val)
