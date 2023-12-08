rule PlugX_J16_Gen2
{
	meta:
		description = "Detects PlugX Malware Samples from June 2016"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research"
		date = "2016-06-08"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "XPlugKeyLogger.cpp" fullword ascii
		$s2 = "XPlugProcess.cpp" fullword ascii
		$s4 = "XPlgLoader.cpp" fullword ascii
		$s5 = "XPlugPortMap.cpp" fullword ascii
		$s8 = "XPlugShell.cpp" fullword ascii
		$s11 = "file: %s, line: %d, error: [%d]%s" fullword ascii
		$s12 = "XInstall.cpp" fullword ascii
		$s13 = "XPlugTelnet.cpp" fullword ascii
		$s14 = "XInstallUAC.cpp" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and (2 of ($s*))) or (5 of them )
}
