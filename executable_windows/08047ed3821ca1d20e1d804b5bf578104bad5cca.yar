import "pe"

rule INDICATOR_KB_CERT_00ad255d4ebefa751f3782587396c08629
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8fa4298057066c9ef96c28b2dd065e8896327658"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Ornitek" and pe.signatures[i].serial=="00:ad:25:5d:4e:be:fa:75:1f:37:82:58:73:96:c0:86:29")
}
