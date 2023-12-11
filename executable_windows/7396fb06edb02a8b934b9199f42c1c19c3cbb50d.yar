import "pe"

rule INDICATOR_KB_CERT_00b8f726508cf1d7b7913bf4bbd1e5c19c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0711adcedb225b82dc32c1435ff32d0a1e54911a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TMerkuri LLC" and (pe.signatures[i].serial=="b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c" or pe.signatures[i].serial=="00:b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c"))
}
