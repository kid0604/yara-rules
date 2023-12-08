import "pe"

rule INDICATOR_KB_CERT_Sagsanlgs
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a6073f35adbdfe26ddc0f647953acc3a9bd33962"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sagsanlgs" and pe.signatures[i].serial=="00")
}
