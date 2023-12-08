import "pe"

rule PCShrinkerv045
{
	meta:
		author = "malware-lu"
		description = "Detects PCShrinker v0.45 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BD [4] 01 AD E3 38 40 ?? FF B5 DF 38 40 }

	condition:
		$a0 at pe.entry_point
}
