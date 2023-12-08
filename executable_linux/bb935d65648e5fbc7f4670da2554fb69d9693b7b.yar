rule SUSP_ELF_SPARC_Hunting_SBZ_Obfuscation
{
	meta:
		description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
		author = "netadr, modified by Florian Roth to avoid elf module import"
		reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
		date = "2023-04-02"
		modified = "2023-05-08"
		score = 60
		os = "linux"
		filetype = "executable"

	strings:
		$xor_block = { 9A 18 E0 47 9A 1B 40 01 9A 18 80 0D }
		$a1 = "SUNW_"

	condition:
		uint32be(0)==0x7f454c46 and $a1 and $xor_block
}
