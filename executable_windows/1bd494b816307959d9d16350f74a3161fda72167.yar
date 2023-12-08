import "pe"

rule EXEStealth275WebtoolMaster
{
	meta:
		author = "malware-lu"
		description = "Detects the EXEStealth275WebtoolMaster malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
