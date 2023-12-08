import "pe"

rule INDICATOR_KB_CERT_1c7d3f6e116554809f49ce16ccb62e84
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = ""
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "1549 LIMITED" and pe.signatures[i].serial=="1c:7d:3f:6e:11:65:54:80:9f:49:ce:16:cc:b6:2e:84")
}
