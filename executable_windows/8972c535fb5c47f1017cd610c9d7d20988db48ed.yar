rule APT30_Sample_25
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "44a21c8b3147fabc668fee968b62783aa9d90351"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\WINDOWS" fullword ascii
		$s2 = "aragua" fullword ascii
		$s4 = "\\driver32\\7$" ascii
		$s8 = "System V" fullword ascii
		$s9 = "Compu~r" fullword ascii
		$s10 = "PROGRAM L" fullword ascii
		$s18 = "GPRTMAX" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
