import "pe"

rule INDICATOR_KB_CERT_aec009984fa957f3f48fe3104ca9babc
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9d5b6bc86775395992a25d21d696d05d634a89d1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ceefaccdedbfbbaaaadacdbf" and pe.signatures[i].serial=="ae:c0:09:98:4f:a9:57:f3:f4:8f:e3:10:4c:a9:ba:bc")
}
