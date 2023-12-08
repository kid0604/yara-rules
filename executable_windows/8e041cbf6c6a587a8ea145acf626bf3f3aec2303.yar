import "pe"

rule Slingshot_APT_Minisling
{
	meta:
		description = "Detects malware from Slingshot APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/apt-slingshot/84312/"
		date = "2018-03-09"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "{6D29520B-F138-442e-B29F-A4E7140F33DE}" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of them
}
