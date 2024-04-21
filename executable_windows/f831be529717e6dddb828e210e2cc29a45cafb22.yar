import "pe"

rule spoolsv_kaslose_7
{
	meta:
		description = "for files:  spoolsv.exe, kaslose.dll"
		author = "TheDFIRReport"
		date = "2021-09-14"
		hash1 = "0d575c22dfd30ca58f86e4cf3346180f2a841d2105a3dacfe298f9c7a22049a0"
		hash2 = "320296ea54f7e957f4fc8d78ec0c1658d1c04a22110f9ddffa6e5cb633a1679c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Protect End" fullword ascii
		$s2 = "ctsTpiHgtme0JSV3" fullword ascii
		$s3 = "Protect Begin" fullword ascii
		$s4 = "pZs67CJpQCgMm8L4" fullword ascii
		$s5 = "6V7e7z7" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and ( all of them )) or ( all of them )
}
