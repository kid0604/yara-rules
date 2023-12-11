import "pe"

rule INDICATOR_KB_CERT_00aa1d84779792b57f91fe7a4bde041942
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6c15651791ea8d91909a557eadabe3581b4d1be9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AXIUM NORTHWESTERN HYDRO INC." and (pe.signatures[i].serial=="aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42" or pe.signatures[i].serial=="00:aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42"))
}
