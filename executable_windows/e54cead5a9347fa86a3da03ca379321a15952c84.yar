import "pe"

rule Microcin_Sample_4
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		date = "2017-09-26"
		hash1 = "92c01d5af922bdaacb6b0b2dfbe29e5cc58c45cbee5133932a499561dab616b8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd /c dir /a /s \"%s\" > \"%s\"" fullword wide
		$s2 = "ini.dat" fullword wide
		$s3 = "winupdata" fullword wide
		$f1 = "%s\\(%08x%08x)%s" fullword wide
		$f2 = "%s\\d%08x\\d%08x.db" fullword wide
		$f3 = "%s\\u%08x\\u%08x.db" fullword wide
		$f4 = "%s\\h%08x\\h%08x.db" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of ($s*) or 5 of them )
}
