import "pe"

rule INDICATOR_KB_CERT_5fb6bae8834edd8d3d58818edc86d7d7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "026868bbc22c6a37094851e0c6f372da90a8776b01f024badb03033706828088"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tramplink LLC" and pe.signatures[i].serial=="5f:b6:ba:e8:83:4e:dd:8d:3d:58:81:8e:dc:86:d7:d7")
}
