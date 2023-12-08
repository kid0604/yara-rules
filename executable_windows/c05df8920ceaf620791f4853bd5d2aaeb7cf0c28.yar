import "pe"

rule EPExEPackV10EliteCodingGroup
{
	meta:
		author = "malware-lu"
		description = "Detects the EPack v1.0 packer used by EliteCodingGroup"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 68 [4] B8 [4] FF 10 }

	condition:
		$a0 at pe.entry_point
}
