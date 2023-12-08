import "pe"

rule INDICATOR_KB_CERT_2095c6f1eadb65ce02862bd620623b92
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "940a4d4a5aadef70d8c14caac6f11d653e71800f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Febeecad" and pe.signatures[i].serial=="20:95:c6:f1:ea:db:65:ce:02:86:2b:d6:20:62:3b:92")
}
