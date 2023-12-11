import "pe"

rule Foudre_Backdoor_SFX
{
	meta:
		description = "Detects Foudre Backdoor SFX"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Nbqbt6"
		date = "2017-08-01"
		hash1 = "2b37ce9e31625d8b9e51b88418d4bf38ed28c77d98ca59a09daab01be36d405a"
		hash2 = "4d51a0ea4ecc62456295873ff135e4d94d5899c4de749621bafcedbf4417c472"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "main.exe" fullword ascii
		$s2 = "pub.key" fullword ascii
		$s3 = "WinRAR self-extracting archive" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
