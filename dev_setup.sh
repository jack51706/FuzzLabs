#!/bin/bash

apt-get install git npm python-daemon python-bluez python-ipaddr python-psutil python-pip pylint pychecker libjson0 libjson0-dev
pip install PyDispatcher
npm config set registry http://registry.npmjs.org/
npm install -g bower

