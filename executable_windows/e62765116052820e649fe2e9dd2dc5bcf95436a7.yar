rule APT30_Sample_23
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "9865e24aadb4480bd3c182e50e0e53316546fc01"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "hostid" ascii
		$s1 = "\\Window" ascii
		$s2 = "%u:%u%s" fullword ascii
		$s5 = "S2tware\\Mic" ascii
		$s6 = "la/4.0 (compa" ascii
		$s7 = "NameACKernel" fullword ascii
		$s12 = "ToWideChc[lo" fullword ascii
		$s14 = "help32SnapshotfL" ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
