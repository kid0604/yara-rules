import "pe"

rule INDICATOR_KB_CERT_121fca3cfa4bd011669f5cc4e053aa3f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "84b5ef4f981020df2385754ab1296821fa2f8977"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kymijoen Projektipalvelut Oy" and pe.signatures[i].serial=="12:1f:ca:3c:fa:4b:d0:11:66:9f:5c:c4:e0:53:aa:3f")
}
