import "pe"

rule INDICATOR_KB_CERT_b4f42e2c153c904fda64c957ed7e1028
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ed4c50ab4f173cf46386a73226fa4dac9cadc1c4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NONO spol. s r.o." and pe.signatures[i].serial=="b4:f4:2e:2c:15:3c:90:4f:da:64:c9:57:ed:7e:10:28")
}
