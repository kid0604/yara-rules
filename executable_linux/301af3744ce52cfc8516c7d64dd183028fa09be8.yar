import "pe"

rule SUSP_ELF_Invalid_Version
{
	meta:
		desc = "Identify ELF file that has mangled header info."
		author = "@shellcromancer"
		version = "0.1"
		score = 55
		last_modified = "2023.01.01"
		reference = "https://n0.lol/ebm/1.html"
		reference = "https://tmpout.sh/1/1.html"
		hash = "05379bbf3f46e05d385bbd853d33a13e7e5d7d50"
		description = "Identify ELF file that has mangled header info."
		os = "linux"
		filetype = "executable"

	condition:
		( uint32(0)==0x464c457f and uint8(0x6)>1)
}
