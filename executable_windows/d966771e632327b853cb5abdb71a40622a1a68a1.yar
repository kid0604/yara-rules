import "pe"

rule PCShrinkerv029
{
	meta:
		author = "malware-lu"
		description = "Detects PCShrinker version 029"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BD [4] 01 AD 55 39 40 ?? 8D B5 35 39 40 }

	condition:
		$a0 at pe.entry_point
}
