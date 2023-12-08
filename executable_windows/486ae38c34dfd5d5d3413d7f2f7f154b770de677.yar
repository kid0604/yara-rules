import "pe"

rule INDICATOR_KB_CERT_2a52acb34bd075ac9f58771d2a4bbfba
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c839065a159bec7e63bfdcb1794889829853c07f7a931666f4eb84103302c1c9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Katarzyna Galganek mim e coc" and pe.signatures[i].serial=="2a:52:ac:b3:4b:d0:75:ac:9f:58:77:1d:2a:4b:bf:ba")
}
