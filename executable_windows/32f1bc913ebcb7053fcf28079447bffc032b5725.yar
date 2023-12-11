rule update_PcMain
{
	meta:
		description = "Chinese Hacktool Set - file PcMain.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "aa68323aaec0269b0f7e697e69cce4d00a949caa"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322" ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
		$s2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" fullword ascii
		$s3 = "\\svchost.exe -k " fullword ascii
		$s4 = "SYSTEM\\ControlSet001\\Services\\%s" fullword ascii
		$s9 = "Global\\%s-key-event" fullword ascii
		$s10 = "%d%d.exe" fullword ascii
		$s14 = "%d.exe" fullword ascii
		$s15 = "Global\\%s-key-metux" fullword ascii
		$s18 = "GET / HTTP/1.1" fullword ascii
		$s19 = "\\Services\\" fullword ascii
		$s20 = "qy001id=%d;qy001guid=%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 4 of them
}
