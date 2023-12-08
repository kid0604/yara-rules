rule APT30_Sample_19
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/03"
		modified = "2023-01-06"
		score = 75
		hash = "cfa438449715b61bffa20130df8af778ef011e15"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
		$s1 = "%s,Volume:%s,Type:%s,TotalSize:%uMB,FreeSize:%uMB" fullword ascii
		$s2 = "\\TEMP\\" ascii
		$s3 = "\\Temporary Internet Files\\" ascii
		$s5 = "%s TotalSize:%u Bytes" fullword ascii
		$s6 = "This Disk Maybe a Encrypted Flash Disk!" fullword ascii
		$s7 = "User:%-32s" fullword ascii
		$s8 = "\\Desktop\\" ascii
		$s9 = "%s.%u_%u" fullword ascii
		$s10 = "Nick:%-32s" fullword ascii
		$s11 = "E-mail:%-32s" fullword ascii
		$s13 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
		$s14 = "Type:%-8s" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and 8 of them
}
