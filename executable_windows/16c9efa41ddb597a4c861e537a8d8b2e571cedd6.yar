import "pe"

rule INDICATOR_KB_CERT_56bba7fe242e6b49695bcf07870f5f5e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3c176bff246a30460311e8c71f880cad2a845164"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ewGMiQgCHj" and pe.signatures[i].serial=="56:bb:a7:fe:24:2e:6b:49:69:5b:cf:07:87:0f:5f:5e")
}
