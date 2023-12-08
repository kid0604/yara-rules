import "pe"

rule INDICATOR_KB_CERT_24c1ef800f275ab2780280c595de3464
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "836b81154eb924fe741f50a21db258da9b264b85"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HOLGAN LIMITED" and pe.signatures[i].serial=="24:c1:ef:80:0f:27:5a:b2:78:02:80:c5:95:de:34:64")
}
