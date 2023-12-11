import "pe"

rule INDICATOR_KB_CERT_1389c8373c00b792207bca20aa40aa40
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "38f65d64ac93f080b229ab83cb72619b0754fa6f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VITA-DE d.o.o." and pe.signatures[i].serial=="13:89:c8:37:3c:00:b7:92:20:7b:ca:20:aa:40:aa:40")
}
