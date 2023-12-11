import "pe"

rule INDICATOR_KB_CERT_00c8edcfe8be174c2f204d858c5b91dea5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7f5f205094940793d1028960e0f0e8b654f9956e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Paarcopy Oy" and pe.signatures[i].serial=="00:c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5")
}
