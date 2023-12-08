import "pe"

rule INDICATOR_KB_CERT_6bec31a0a40d2e834e51ae704e1bf9d3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7a236872302156c58d493b63a1607a09c4f1d0b8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "whatsupfuckers" and pe.signatures[i].serial=="6b:ec:31:a0:a4:0d:2e:83:4e:51:ae:70:4e:1b:f9:d3")
}
