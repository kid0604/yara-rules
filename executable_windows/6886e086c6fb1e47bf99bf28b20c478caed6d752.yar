rule APT30_Sample_15
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "7a8576804a2bbe4e5d05d1718f90b6a4332df027"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\Windo" ascii
		$s2 = "HHOSTR" ascii
		$s3 = "Softwa]\\Mic" ascii
		$s4 = "Startup'T" fullword ascii
		$s17 = "help32Snapshot0L" fullword ascii
		$s18 = "TimUmoveH" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
