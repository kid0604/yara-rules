import "pe"

private rule WindowsPE
{
	meta:
		description = "Yara rule to detect Windows PE files"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550
}
