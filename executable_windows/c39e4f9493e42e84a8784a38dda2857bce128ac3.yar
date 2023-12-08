import "pe"

rule malware_apt15_royaldll
{
	meta:
		author = "David Cannings"
		description = "DLL implant, originally rights.dll and runs as a service"
		sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
		os = "windows"
		filetype = "executable"

	strings:
		$opcodes_jshash = { B8 A7 C6 67 4E 83 C1 02 BA 04 00 00 00 57 90 }
		$opcodes_encode = { 0F B6 1C 03 8B 55 08 30 1C 17 47 3B 7D 0C }
		$opcodes_sleep_loop = { 68 (88|B8) (13|0B) 00 00 FF D6 4F 75 F6 }
		$ = "Nwsapagent" fullword
		$ = "\"%s\">>\"%s\"\\s.txt"
		$ = "myWObject" fullword
		$ = "del c:\\windows\\temp\\r.exe /f /q"
		$ = "del c:\\windows\\temp\\r.ini /f /q"

	condition:
		3 of them
}
