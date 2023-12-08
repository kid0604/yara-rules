import "pe"

rule INDICATOR_KB_CERT_41f8253e1ceafbfd8e49f32c34a68f9e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "02e739740b88328ac9c4a6de0ee703b7610f977b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Shenzhen Smartspace Software technology Co.,Limited" and pe.signatures[i].serial=="41:f8:25:3e:1c:ea:fb:fd:8e:49:f3:2c:34:a6:8f:9e")
}
