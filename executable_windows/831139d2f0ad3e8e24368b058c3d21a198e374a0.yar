import "pe"

rule INDICATOR_KB_CERT_00ece6cbf67dc41635a5e5d075f286af23
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f1f83c96ab00dcb70c0231d946b6fbd6a01e2c94e8f9f30352bbe50e89a9a51c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THRANE AGENTUR ApS" and pe.signatures[i].serial=="00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23")
}
