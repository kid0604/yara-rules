import "pe"

rule INDICATOR_KB_CERT_62b80fc5e1c02072019c88ee356152c1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0a83c0f116020fc1f43558a9a08b1f8bcbb809e0"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Inversum" and pe.signatures[i].serial=="62:b8:0f:c5:e1:c0:20:72:01:9c:88:ee:35:61:52:c1")
}
