#!/bin/bash

safe akms2 -e msg msg.enc test.ecc.pk && safe akms2 -d msg.enc msg.dec test.ecc.sk
