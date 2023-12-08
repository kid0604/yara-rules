import "pe"

rule RUAG_Tavdig_Malformed_Executable
{
	meta:
		description = "Detects an embedded executable with a malformed header - known from Tavdig malware"
		author = "Florian Roth"
		reference = "https://goo.gl/N5MEj0"
		score = 60
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3C))==0x0000AD0B
}
