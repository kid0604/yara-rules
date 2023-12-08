rule APT30_Generic_F
{
	meta:
		description = "FireEye APT30 Report Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "09010917cd00dc8ddd21aeb066877aa2"
		hash2 = "4c10a1efed25b828e4785d9526507fbc"
		hash3 = "b7b282c9e3eca888cbdb5a856e07e8bd"
		hash4 = "df1799845b51300b03072c6569ab96d5"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\~zlzl.exe" ascii
		$s2 = "\\Internet Exp1orer" ascii
		$s3 = "NodAndKabIsExcellent" fullword ascii

	condition:
		filesize <100KB and uint16(0)==0x5A4D and all of them
}
