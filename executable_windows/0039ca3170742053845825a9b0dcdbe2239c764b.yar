import "pe"

rule INDICATOR_KB_CERT_9d915138acdac1a044afa6e5d99567c5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4f8b9ce0e25810d1b62d8c016607de128beba2a1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AAAruntest" and pe.signatures[i].serial=="9d:91:51:38:ac:da:c1:a0:44:af:a6:e5:d9:95:67:c5")
}
