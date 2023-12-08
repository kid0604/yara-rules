import "pe"

rule DragonFly_APT_Sep17_4
{
	meta:
		description = "Detects malware from DrqgonFly APT report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
		date = "2017-09-12"
		hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "screen.exe" fullword wide
		$s2 = "PlatformInvokeUSER32" fullword ascii
		$s3 = "GetDesktopImageF" fullword ascii
		$s4 = "PlatformInvokeGDI32" fullword ascii
		$s5 = "GetDesktopImage" fullword ascii
		$s6 = "Too many arguments, going to store in current dir" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <60KB and all of them )
}
