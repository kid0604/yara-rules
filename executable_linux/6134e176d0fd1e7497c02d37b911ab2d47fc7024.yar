rule SUSP_ELF_SPARC_Hunting_SBZ_ModuleStruct
{
	meta:
		description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
		author = "netadr, modified by Florian Roth for FP reduction reasons"
		reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
		date = "2023-04-02"
		modified = "2023-05-08"
		score = 60
		os = "linux"
		filetype = "executable"

	strings:
		$be = { 02 02 00 00 01 C1 00 07 }
		$le = { 02 02 00 00 07 00 C1 01 }

	condition:
		uint32be(0)==0x7f454c46 and ($be or $le)
}
