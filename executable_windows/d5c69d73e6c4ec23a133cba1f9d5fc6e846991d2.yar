import "pe"

rule Silence_malware_1
{
	meta:
		description = "Detects malware sample mentioned in the Silence report on Securelist"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/the-silence/83009/"
		date = "2017-11-01"
		hash1 = "f24b160e9e9d02b8e31524b8a0b30e7cdc66dd085e24e4c58240e4c4b6ec0ac2"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "adobeudp.exe" fullword wide
		$x2 = "%s\\adobeudp.exeZone.Identifier" fullword ascii
		$x3 = "%s\\igfxpers_%08x.exe" fullword ascii
		$x4 = "%s\\adobeudp.exe" fullword ascii
		$s1 = "SoftWare\\MicroSoft\\Windows\\CurrentVersion\\Run" fullword ascii
		$s2 = "Copyright (C)  1999 - 2017" fullword wide
		$s3 = "%sget.php?name=%x" fullword ascii
		$s4 = "VNASSRUNXYC" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="e03edb9bd7cbe200dc59f361db847f8a" or 1 of ($x*) or 3 of them )
}
