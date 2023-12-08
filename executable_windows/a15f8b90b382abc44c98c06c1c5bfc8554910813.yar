import "pe"

rule INDICATOR_KB_CERT_e5b2af04ea4b84a94609a47eba3164ec
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7785d50066faee71d1a463584c1a97f34431ddfe"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RRGRQJRWZHRTLFAUVK" and pe.signatures[i].serial=="e5:b2:af:04:ea:4b:84:a9:46:09:a4:7e:ba:31:64:ec")
}
