import "pe"

rule MALWARE_Win_NETEAGLE
{
	meta:
		author = "ditekSHen"
		description = "NETEAGLE backdoor payload"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
		$s2 = "System\\CurrentControlSet\\control\\ComputerName\\ComputerName" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 5.0; Win32)" fullword ascii
		$s4 = "/index.htm" fullword ascii
		$s5 = "Help_ME" fullword ascii
		$s6 = "GOTO ERROR" ascii
		$s7 = "127.0.0.1" fullword ascii
		$s8 = /pic\d\.bmp/ ascii wide

	condition:
		uint16(0)==0x5a4d and 7 of them
}
