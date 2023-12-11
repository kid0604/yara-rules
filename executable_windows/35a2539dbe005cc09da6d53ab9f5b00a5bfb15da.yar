import "pe"

rule INDICATOR_KB_CERT_e339c8069126aa6313484fea85b4b326f7b8860c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e339c8069126aa6313484fea85b4b326f7b8860c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Germany classer software" and pe.signatures[i].serial=="01")
}
