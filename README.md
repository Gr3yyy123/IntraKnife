# IntarKnife  v1.0

a tool can be used in intarnet for easily pentesting

## moudle

### hash spray

U can use this tool to spray hash on a webshell

```
IntraKnife.exe -m spray -l com.txt -u user.txt -P admin123
IntraKnife.exe -m spray -l com.txt -u user.txt -ha xxxxxxxxxxxxxxxxxxxxxxxxx
```

### search adinfo

U can use this tool to collect adinfo

```
IntraKnife.exe -m spray -m adinfo -d 10.10.1.1 -dn "dc=cia,dc=local" -u cia\administrator -P admin123 -f user
IntraKnife.exe -m spray -m adinfo -d 10.10.1.1 -dn "dc=cia,dc=local" -u cia\administrator -P admin123 -f computer
IntraKnife.exe -m spray -m adinfo -d 10.10.1.1 -dn "dc=cia,dc=local" -u cia\administrator -P admin123 -f group
```

### parse DNS

U can use this tool to get the machine's ip by their hostname

```
IntraKnife.exe -m dns -l com.txt
```

### list share

U can use this tool to list shares

```
IntraKnife.exe -m share -l com.txt -u cia/administrator -p admin123
IntraKnife.exe -m share -l com.txt -u cia/administrator -ha xxxxxxxxxxxxxxxxxxxxxxxx
```

### find active

U can use this tool to find the active host in intranet (with ping)

```
IntraKnife.exe -m active -l com.txt
```

