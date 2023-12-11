import "pe"

rule INDICATOR_KB_CERT_5c7e78f53c31d6aa5b45de14b47eb5c4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f91d436c1c7084b83007f032ef48fecda382ff8b81320212adb81e462976ad5a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cubic Information Systems, UAB" and pe.signatures[i].serial=="5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4")
}
