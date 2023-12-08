import "pe"

rule INDICATOR_KB_CERT_4b03cabe6a0481f17a2dbeb9aefad425
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2e86cb95aa7e4c1f396e236b41bb184787274bb286909b60790b98f713b58777"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RASSVET, OOO" and pe.signatures[i].serial=="4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25")
}
