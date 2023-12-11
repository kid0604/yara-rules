import "pe"

rule ASPackv107bAlexeySolodovnikov
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ASPack v1.07b Alexey Solodovnikov packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED [4] B8 [4] 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE [2] 80 BD 01 DE }

	condition:
		$a0 at pe.entry_point
}
