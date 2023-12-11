import "pe"

rule INDICATOR_KB_CERT_00b7f19b13de9bee8a52ff365ced6f67fa
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "61708a3a2bae5343ff764de782d7f344151f2b74"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ALEXIS SECURITY GROUP, LLC" and pe.signatures[i].serial=="00:b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa")
}
