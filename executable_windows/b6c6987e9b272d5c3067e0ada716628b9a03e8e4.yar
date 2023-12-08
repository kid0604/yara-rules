import "pe"

rule CERBERUSv20
{
	meta:
		author = "malware-lu"
		description = "Detects CERBERUSv20 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 2B ED 8C [2] 8C [2] FA E4 ?? 88 [2] 16 07 BF [2] 8E DD 9B F5 B9 [2] FC F3 A5 }

	condition:
		$a0 at pe.entry_point
}
