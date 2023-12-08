import "pe"

rule INDICATOR_KB_CERT_32fbf8cfa43dca3f85efabe96dfefa49
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "498d63bf095195828780dba7b985b71ab08e164f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Foxstyle LLC" and pe.signatures[i].serial=="32:fb:f8:cf:a4:3d:ca:3f:85:ef:ab:e9:6d:fe:fa:49")
}
