rule APT30_Generic_K
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/03"
		modified = "2023-01-06"
		score = 75
		hash = "142bc01ad412799a7f9ffed994069fecbd5a2f93"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Maybe a Encrypted Flash" fullword ascii
		$s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
		$s1 = "\\TEMP\\" ascii
		$s2 = "\\Temporary Internet Files\\" ascii
		$s5 = "%s Size:%u Bytes" fullword ascii
		$s7 = "$.DATA$" fullword ascii
		$s10 = "? Size:%u By s" fullword ascii
		$s12 = "Maybe a Encrypted Flash" fullword ascii
		$s14 = "Name:%-32s" fullword ascii
		$s15 = "NickName:%-32s" fullword ascii
		$s19 = "Email:%-32s" fullword ascii
		$s21 = "C:\\Prog" ascii
		$s22 = "$LDDATA$" ascii
		$s31 = "Copy File %s OK!" fullword ascii
		$s32 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
		$s34 = "open=%s" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and ( all of ($x*) and 3 of ($s*))
}
