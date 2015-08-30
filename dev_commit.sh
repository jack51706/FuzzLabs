#!/bin/bash

./fuzzlabs.py stop
sleep 2
find ./ -name "*.pyc" -type f -exec rm {} \;
find ./jobs/ -name "*.crash*" -type f -exec rm {} \;
find ./jobs/ -name "*.session" -type f -exec rm {} \;
find ./agents/ -name "*.o" -type f -exec rm {} \;

git add -A .
git commit -m "$1"
git push origin master

