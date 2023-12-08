import "pe"

rule INDICATOR_KB_CERT_2c1ee9b583310b5e34a1ee6945a34b26
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7af96a09b6c43426369126cfffac018f11e5562cb64d32e5140cff3f138ffea4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Artmarket" and pe.signatures[i].serial=="2c:1e:e9:b5:83:31:0b:5e:34:a1:ee:69:45:a3:4b:26")
}
