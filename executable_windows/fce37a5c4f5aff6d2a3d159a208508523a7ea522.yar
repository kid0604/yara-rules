import "pe"

rule INDICATOR_KB_CERT_43a36a26ebc78e111a874d8211a95e3f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a346bda33b5b3bea04b299fe87c165c4f221645a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Efacefcafeabbdcbcea" and pe.signatures[i].serial=="43:a3:6a:26:eb:c7:8e:11:1a:87:4d:82:11:a9:5e:3f")
}
