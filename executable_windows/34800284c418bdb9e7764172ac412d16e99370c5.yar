import "pe"

rule INDICATOR_KB_CERT_35590ebe4a02dc23317d8ce47a947a9b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d9b60a67cf3c8964be1e691d22b97932d40437bfead97a84c1350a2c57914f28"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Largos" and pe.signatures[i].serial=="35:59:0e:be:4a:02:dc:23:31:7d:8c:e4:7a:94:7a:9b")
}
