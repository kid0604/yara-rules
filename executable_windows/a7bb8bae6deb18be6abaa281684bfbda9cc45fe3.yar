rule APT30_Sample_9
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "442bf8690401a2087a340ce4a48151c39101652f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\Windo" ascii
		$s2 = "oHHOSTR" ascii
		$s3 = "Softwa]\\Mic" ascii
		$s4 = "Startup'T" ascii
		$s6 = "Ora\\%^" ascii
		$s7 = "\\Ohttp=r" ascii
		$s17 = "help32Snapshot0L" ascii
		$s18 = "TimUmoveH" ascii
		$s20 = "WideChc[lobalAl" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
