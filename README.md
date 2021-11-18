# IntarKnife  v1.0

a tool can be used in intarnet for easily pentesting

## moudle

### hash spray

U can use this tool to spray hash on a webshell

```
IntraKnife.exe -m spray -l com.txt -U user.txt -P admin123
IntraKnife.exe -m spray -l com.txt -U user.txt -ha xxxxxxxxxxxxxxxxxxxxxxxxx
```
u can use `-A` to check if this user has wmi permission

```
IntraKnife.exe -m spray -l com.txt -U user.txt -P admin123 -A
IntraKnife.exe -m spray -l com.txt -U user.txt -ha xxxxxxxxxxxxxxxxxxxxxxxxx -A
```

### search adinfo

U can use this tool to collect adinfo

```
IntraKnife.exe -m adinfo -d 10.10.1.1 -dm cia.local -u cia\administrator -P admin123 -f user
IntraKnife.exe -m adinfo -d 10.10.1.1 -dm cia.local -u cia\administrator -P admin123 -f computer
IntraKnife.exe -m adinfo -d 10.10.1.1 -dm cia.local -u cia\administrator -P admin123 -f group
```
or u can use `-a` point the attribute
```
IntraKnife.exe -m adinfo -d 10.10.1.1 -dm cia.local -u cia\administrator -P admin123 -f user -a samaccountname,mail
```

### parse DNS

U can use this tool to get the machine's ip by their hostname

```
IntraKnife.exe -m dns -l com.txt
```

### list share

U can use this tool to list shares

```
IntraKnife.exe -m share -l com.txt -u cia\administrator -p admin123
IntraKnife.exe -m share -l com.txt -u cia\administrator -ha xxxxxxxxxxxxxxxxxxxxxxxx
```
or u can just try an anonymous share

```
IntraKnife.exe -m share -l com.txt
```

### find active

U can use this tool to find the active host in intranet (with ping)

```
IntraKnife.exe -m active -l com.txt
```
now cidr format is supported

```
IntraKnife.exe -m active -c 10.10.1.1/24
```

## Time sec

sometimes u could send request slowly to escape EDR,this may take longer time but keep u silent

```
IntraKnife.exe -m spray -l com.txt -U user.txt -P admin123 -t 1 -T 20 
```
