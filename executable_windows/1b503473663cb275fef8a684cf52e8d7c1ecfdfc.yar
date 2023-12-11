import "pe"

rule INDICATOR_KB_CERT_734d0baf7a6b44743ff852c8ba7a751a7ff0ec73
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "734d0baf7a6b44743ff852c8ba7a751a7ff0ec73"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Transition software (C) 2018" and pe.signatures[i].serial=="01")
}
