import "pe"

rule VirogensPEShrinkerv014
{
	meta:
		author = "malware-lu"
		description = "Detects Virogens PE Shrinker version 0.14"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 55 E8 [4] 87 D5 5D 60 87 D5 8D [5] 8D [5] 57 56 AD 0B C0 74 }

	condition:
		$a0 at pe.entry_point
}
