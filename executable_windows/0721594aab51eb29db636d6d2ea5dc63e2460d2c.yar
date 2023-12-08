import "pe"

rule RpolycryptbyVaska2003071841
{
	meta:
		author = "malware-lu"
		description = "Detects the Polycrypt malware variant by Vaska2003071841"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 58 [7] E8 00 00 00 58 E8 00 [45] 00 00 00 [2] 04 }

	condition:
		$a0
}
