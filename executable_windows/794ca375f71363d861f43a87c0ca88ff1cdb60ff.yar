import "pe"

rule INDICATOR_KB_CERT_778906d40695f65ba518db760df44cd3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1103debcb1e48f7dda9cec4211c0a7a9c1764252"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="77:89:06:d4:06:95:f6:5b:a5:18:db:76:0d:f4:4c:d3")
}
