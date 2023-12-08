rule IronPanda_DNSTunClient
{
	meta:
		description = "Iron Panda malware DnsTunClient - file named.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		score = 80
		hash = "a08db49e198068709b7e52f16d00a10d72b4d26562c0d82b4544f8b0fb259431"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "dnstunclient -d or -domain <domain>" fullword ascii
		$s2 = "dnstunclient -ip <server ip address>" fullword ascii
		$s3 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"\\Microsoft\\Windows\\PLA\\System\\Microsoft Windows\" /tr " fullword ascii
		$s4 = "C:\\Windows\\System32\\cmd.exe /C schtasks /create /tn \"Microsoft Windows\" /tr " fullword ascii
		$s5 = "taskkill /im conime.exe" fullword ascii
		$s6 = "\\dns control\\t-DNSTunnel\\DnsTunClient\\DnsTunClient.cpp" ascii
		$s7 = "UDP error:can not bing the port(if there is unclosed the bind process?)" fullword ascii
		$s8 = "use error domain,set domain pls use -d or -domain mark(Current: %s,recv %s)" fullword ascii
		$s9 = "error: packet num error.the connection have condurt,pls try later" fullword ascii
		$s10 = "Coversation produce one error:%s,coversation fail" fullword ascii
		$s11 = "try to add many same pipe to select group(or mark is too easy)." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 2 of them ) or 5 of them
}
