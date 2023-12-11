rule APT30_Sample_8
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "9531e21652143b8b129ab8c023dc05fef2a17cc3"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "ateProcessA" ascii
		$s1 = "Ternel32.dllFQ" fullword ascii
		$s2 = "StartupInfoAModuleHand" fullword ascii
		$s3 = "OpenMutex" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
