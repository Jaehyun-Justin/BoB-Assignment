#!/bin/sh
/sbin/ifconfig | grep 'ens33' | tr -s ' ' | cut -d ' ' -f5
