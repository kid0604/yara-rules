import "pe"

rule Disclosed_0day_POCs_exploit
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		hash1 = "632d35a0bac27c9b2f3f485d43ebba818089cf72b3b8c4d2e87ce735b2e67d7e"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Release\\exploit.pdb" ascii
		$x2 = "\\favorites\\stolendata.txt" wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 1 of them )
}
