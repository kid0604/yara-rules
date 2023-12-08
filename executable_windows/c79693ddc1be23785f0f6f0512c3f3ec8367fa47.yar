import "pe"

rule APT_Lazarus_Aug18_1
{
	meta:
		description = "Detects Lazarus Group Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/operation-applejeus/87553/"
		date = "2018-08-24"
		hash1 = "ef400d73c6920ac811af401259e376458b498eb0084631386136747dfc3dcfa8"
		hash2 = "1b8d3e69fc214cb7a08bef3c00124717f4b4d7fd6be65f2829e9fd337fc7c03c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mws2_32.dll" fullword wide
		$s2 = "%s.bat" fullword wide
		$s3 = "%s%s%s \"%s > %s 2>&1\"" fullword wide
		$s4 = "Microsoft Corporation. All rights reserved." fullword wide
		$s5 = "ping 127.0.0.1 -n 3" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (pe.imphash()=="3af996e4f960108533e69b9033503f40" or 4 of them )
}
