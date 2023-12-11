import "pe"

rule malware_apt15_royalcli_1
{
	meta:
		description = "Generic strings found in the Royal CLI tool"
		author = "David Cannings"
		sha256 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "%s~clitemp%08x.tmp" fullword
		$ = "%s /c %s>%s" fullword
		$ = "%snewcmd.exe" fullword
		$ = "%shkcmd.exe" fullword
		$ = "%s~clitemp%08x.ini" fullword
		$ = "myRObject" fullword
		$ = "myWObject" fullword
		$ = "2 %s  %d 0 %d\x0D\x0A"
		$ = "2 %s  %d 1 %d\x0D\x0A"
		$ = "%s file not exist" fullword

	condition:
		uint16(0)==0x5A4D and 5 of them
}
