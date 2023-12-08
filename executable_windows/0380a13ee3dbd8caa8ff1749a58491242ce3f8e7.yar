rule CN_Honker_sig_3389_80_AntiFW
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AntiFW.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5fbc75900e48f83d0e3592ea9fa4b70da72ccaa3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Set TS to port:80 Successfully!" fullword ascii
		$s2 = "Now,set TS to port 80" fullword ascii
		$s3 = "echo. >>amethyst.reg" fullword ascii
		$s4 = "del amethyst.reg" fullword ascii
		$s5 = "AntiFW.cpp" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and 2 of them
}
