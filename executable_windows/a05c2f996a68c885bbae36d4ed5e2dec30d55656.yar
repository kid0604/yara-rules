import "pe"

rule INDICATOR_KB_CERT_1966bc76bda1a708334792da9a336f69
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "29fec27c36efc6809c7269f76cf86ee18cc6ed87"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SYNTHETIC LABS LIMITED" and pe.signatures[i].serial=="19:66:bc:76:bd:a1:a7:08:33:47:92:da:9a:33:6f:69")
}
