rule APT30_Sample_31
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "8b4271167655787be1988574446125eae5043aca"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\ZJRsv.tem" ascii
		$s1 = "forceguest" fullword ascii
		$s4 = "\\$NtUninstallKB570317$" ascii
		$s8 = "[Can'tGetIP]" fullword ascii
		$s14 = "QWERTY:,`/" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
