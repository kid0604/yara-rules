import "pe"

rule INDICATOR_KB_CERT_68b050aa3d2c16f77e14a16dc8d1c1ac
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "c757e09e7dc5859dbd00b0ccfdd006764c557a3d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLOW POKE LTD" and pe.signatures[i].serial=="68:b0:50:aa:3d:2c:16:f7:7e:14:a1:6d:c8:d1:c1:ac")
}
