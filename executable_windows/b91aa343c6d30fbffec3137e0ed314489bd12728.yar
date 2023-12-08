import "pe"

rule TA17_318A_rc4_stack_key_fallchill
{
	meta:
		description = "HiddenCobra FallChill - rc4_stack_key"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
		date = "2017-11-15"
		os = "windows"
		filetype = "executable"

	strings:
		$stack_key = { 0d 06 09 2a ?? ?? ?? ?? 86 48 86 f7 ?? ?? ?? ?? 0d 01 01 01 ?? ?? ?? ?? 05 00 03 82 41 8b c9 41 8b d1 49 8b 40 08 48 ff c2 88 4c 02 ff ff c1 81 f9 00 01 00 00 7c eb }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $stack_key
}
