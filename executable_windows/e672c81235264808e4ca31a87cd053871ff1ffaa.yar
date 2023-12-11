import "pe"

rule INDICATOR_KB_CERT_8035ed9c58ea895505b05ff926d486bc
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b82a7f87b7d7ccea50bba5fe8d8c1c745ebcb916"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fecddacdddfaadcddcabceded" and pe.signatures[i].serial=="80:35:ed:9c:58:ea:89:55:05:b0:5f:f9:26:d4:86:bc")
}
