rule Txt_lcx
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file lcx.c"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "ddb3b6a5c5c22692de539ccb796ede214862befe"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
		$s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
		$s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
		$s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
		$s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii

	condition:
		filesize <25KB and 2 of them
}
