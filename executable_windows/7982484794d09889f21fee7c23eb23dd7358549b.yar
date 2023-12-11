import "pe"

rule INDICATOR_KB_CERT_0d83e7f47189cdbfc7fa3e5f58882329
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ba4bf6d8caac468c92dd7cd4303cbdb2c9f58886"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and pe.signatures[i].serial=="0d:83:e7:f4:71:89:cd:bf:c7:fa:3e:5f:58:88:23:29")
}
