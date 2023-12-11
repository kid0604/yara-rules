import "pe"

rule MALWARE_Win_MiniDuke
{
	meta:
		author = "ditekSHen"
		description = "Detects MiniDuke"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DefPipe" fullword ascii
		$s2 = "term %5d" fullword ascii
		$s3 = "pid %5d" fullword ascii
		$s4 = "uptime %5d.%02dh" fullword ascii
		$s5 = "login: %s\\%s" fullword ascii
		$s6 = "Software\\Microsoft\\ApplicationManager" ascii
		$s7 = { 69 64 6c 65 ?? 00 73 74 6f 70 ?? 00 61 63 63 65 70 74 ?? 00 63 6f 6e 6e 65 63 74 ?? 00 6c 69 73 74 65 6e ?? 00 }
		$net1 = "salesappliances.com" ascii
		$net2 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36" fullword ascii
		$net3 = "http://10." ascii
		$net4 = "JiM9t8g7j8KoJkLJlKqka8dbo7q5z4v5u3o4z" ascii
		$net5 = "application/octet-stream" ascii
		$net6 = "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"" ascii

	condition:
		uint16(0)==0x5a4d and (5 of ($s*) or 4 of ($net*) or 7 of them )
}
