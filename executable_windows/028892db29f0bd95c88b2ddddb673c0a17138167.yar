import "pe"

rule malware_apt15_royaldll_2
{
	meta:
		author = "Ahmed Zaki"
		sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
		description = "DNS backdoor used by APT15"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" wide ascii
		$ = "netsvcs" wide ascii fullword
		$ = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" wide ascii fullword
		$ = "SYSTEM\\CurrentControlSet\\Services\\" wide ascii
		$ = "myWObject" wide ascii

	condition:
		uint16(0)==0x5A4D and all of them and pe.exports("ServiceMain") and filesize >50KB and filesize <600KB
}
