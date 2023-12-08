import "pe"

rule AcidCrypt : Packer
{
	meta:
		author = "malware-lu"
		description = "Detects the AcidCrypt packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 B9 [3] 00 BA [3] 00 BE [3] 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
		$a1 = { BE [4] 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
