import "pe"

rule INDICATOR_KB_CERT_c4564802095258281a284809930dcf43
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "73db2555f20b171ce9502eb6507add9fa53a5bf3"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cfeaaeedaefddfaaccefcdbae" and pe.signatures[i].serial=="c4:56:48:02:09:52:58:28:1a:28:48:09:93:0d:cf:43")
}
