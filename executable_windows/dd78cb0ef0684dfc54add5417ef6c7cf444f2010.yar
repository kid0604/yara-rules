import "pe"

rule INDICATOR_KB_CERT_008e0fa6b464d466df1b267504b04f7b27
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "91707c95044c5badcd51d198bdbe3a7ff3156c35"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ApcWCjFsGXwbWUJrKZ" and pe.signatures[i].serial=="00:8e:0f:a6:b4:64:d4:66:df:1b:26:75:04:b0:4f:7b:27")
}
