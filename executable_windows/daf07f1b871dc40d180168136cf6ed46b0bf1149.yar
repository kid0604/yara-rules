rule Nautilus_modified_rc4_loop
{
	meta:
		description = "Rule for detection of Nautilus based on assembly code for a modified RC4 loop"
		author = "NCSC UK"
		hash = "a415ab193f6cd832a0de4fcc48d5f53d6f0b06d5e13b3c359878c6c31f3e7ec3"
		date = "2017/11/23"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {42 0F B6 14 04 41 FF C0 03 D7 0F B6 CA 8A 14 0C 43 32 14 13 41 88 12 49 FF C2 49 FF C9}

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $a
}
