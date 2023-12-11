import "pe"

rule INDICATOR_KB_CERT_4808c88ea243eefa47610d5f5f0d02a2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5dc400de1133be3ff17ff09f8a1fd224b3615e5a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bfcdcdfcdfcaaeff" and pe.signatures[i].serial=="48:08:c8:8e:a2:43:ee:fa:47:61:0d:5f:5f:0d:02:a2")
}
