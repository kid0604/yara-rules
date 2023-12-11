import "pe"

rule APT15_Malware_Mar18_RoyalCli
{
	meta:
		description = "Detects malware from APT 15 report by NCC Group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/HZ5XMN"
		date = "2018-03-10"
		hash1 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Release\\RoyalCli.pdb" ascii
		$s2 = "%snewcmd.exe" fullword ascii
		$s3 = "Run cmd error %d" fullword ascii
		$s4 = "%s~clitemp%08x.ini" fullword ascii
		$s5 = "run file failed" fullword ascii
		$s6 = "Cmd timeout %d" fullword ascii
		$s7 = "2 %s  %d 0 %d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 2 of them
}
