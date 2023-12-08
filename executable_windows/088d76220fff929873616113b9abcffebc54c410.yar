import "pe"

rule INDICATOR_KB_CERT_00d9d419c9095a79b1f764297addb935da
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7d45ec21c0d6fd0eb84e4271655eb0e005949614"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Nova soft" and pe.signatures[i].serial=="00:d9:d4:19:c9:09:5a:79:b1:f7:64:29:7a:dd:b9:35:da")
}
