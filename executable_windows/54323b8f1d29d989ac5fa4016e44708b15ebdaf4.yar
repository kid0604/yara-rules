import "pe"

rule INDICATOR_KB_CERT_030ba877daf788a0048d04a85b1f6eca
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1f10c5676a742548fb430fbc1965b20146b7325a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Skylum Software USA, Inc." and pe.signatures[i].serial=="03:0b:a8:77:da:f7:88:a0:04:8d:04:a8:5b:1f:6e:ca")
}
