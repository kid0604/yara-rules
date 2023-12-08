import "pe"

rule DragonFly_APT_Sep17_1
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		date = "2017-09-12"
		hash1 = "fc54d8afd2ce5cb6cc53c46783bf91d0dd19de604308d536827320826bc36ed9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Update\\Temp\\ufiles.txt" wide
		$s2 = "%02d.%02d.%04d %02d:%02d" fullword wide
		$s3 = "*pass*.*" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
