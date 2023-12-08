import "pe"

rule INDICATOR_KB_CERT_a61b5590c2d8dc70a31f8ea78cda4353
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d1f77736e8594e026f67950ca2bf422bb12abc3a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bdddcfaebffbfdcabaffe" and pe.signatures[i].serial=="a6:1b:55:90:c2:d8:dc:70:a3:1f:8e:a7:8c:da:43:53")
}
