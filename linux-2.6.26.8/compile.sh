#!/bin/sh

# remove old modules
sudo su -c '/sbin/rmmod nf_nat_sl'
sudo su -c '/sbin/rmmod nf_conntrack_sl'


make modules
sudo make modules_install

# load new modules
sudo su -c '/sbin/modprobe nf_nat_sl'
sudo su -c '/sbin/modprobe nf_conntrack_sl'



