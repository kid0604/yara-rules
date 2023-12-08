import "pe"

rule INDICATOR_KB_CERT_205483936f360924e8d2a4eb6d3a9f31
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "430dbeff2f6df708b03354d5d07e78400cfed8e9"
		hash1 = "e58b9bbb7bcdf3e901453b7b9c9e514fed1e53565e3280353dccc77cde26a98e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SATURN CONSULTANCY LTD" and pe.signatures[i].serial=="20:54:83:93:6f:36:09:24:e8:d2:a4:eb:6d:3a:9f:31")
}
