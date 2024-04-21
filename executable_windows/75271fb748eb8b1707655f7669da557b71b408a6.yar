rule StealcStrings
{
	meta:
		author = "kevoreilly"
		description = "Stealc string decryption"
		cape_options = "bp0=$decode+17,action0=string:edx,count=1,typestring=Stealc Strings"
		packed = "d0c824e886f14b8c411940a07dc133012b9eed74901b156233ac4cac23378add"
		os = "windows"
		filetype = "executable"

	strings:
		$decode = {51 8B 15 [4] 52 8B 45 ?? 50 E8 [4] 83 C4 0C 6A 04 6A 00 8D 4D ?? 51 FF 15 [4] 83 C4 0C 8B 45 ?? 8B E5 5D C3}

	condition:
		uint16(0)==0x5A4D and any of them
}
