rule APT30_Sample_22
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "0d17a58c24753e5f8fd5276f62c8c7394d8e1481"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "(\\TEMP" fullword ascii
		$s2 = "Windows\\Cur" fullword ascii
		$s3 = "LSSAS.exeJ" fullword ascii
		$s4 = "QC:\\WINDOWS" fullword ascii
		$s5 = "System Volume" fullword ascii
		$s8 = "PROGRAM FILE" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
