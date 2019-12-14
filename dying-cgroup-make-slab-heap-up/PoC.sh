#!/bin/bash

old_memcg_num=$(cat /proc/cgroups | awk '/memory/ {print $3}')

free -m
slabtop -o | head
echo "now the number of memory cgroup is                $old_memcg_num"
echo "begin to create cgroups"

prefix=/sys/fs/cgroup/memory/aklis

for i in {1..1000};
do
  mkdir $prefix-$i;
  bash -c "echo \$\$ > $prefix-$i/tasks; mkdir /tmp/$i; echo 'fubao'>/tmp/$i/pandada8;"
done

created_memcg_num=$(cat /proc/cgroups | awk '/memory/ {print $3}')
free -m
slabtop -o | head

echo "now the number of memory cgroup is                $created_memcg_num"
echo "begin to del cgroups that created by Poc, pddka!"

for i in {1..1000};
do
  rmdir $prefix-$i;
done

free -m
slabtop -o | head
deleted_memcg_num=$(cat /proc/cgroups | awk '/memory/ {print $3}')
echo "now the number of memory cgroup is                $deleted_memcg_num"

echo "P.S. remember to clear the tmp file (/tmp)"
