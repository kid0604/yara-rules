import "pe"

rule Sig_RemoteAdmin_1
{
	meta:
		description = "Detects strings from well-known APT malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-12-03"
		score = 45
		os = "windows"
		filetype = "executable"

	strings:
		$ = "Radmin, Remote Administrator" wide
		$ = "Radmin 3.0" wide

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them
}
