import "pe"

rule EXEStealth276UnregisteredWebtoolMaster
{
	meta:
		author = "malware-lu"
		description = "Detects unregistered webtool master using EXEStealth 2.76"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }

	condition:
		$a0
}
