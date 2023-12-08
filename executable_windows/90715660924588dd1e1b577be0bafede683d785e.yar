import "pe"

rule INDICATOR_KB_CERT_035b41766660b08aaf121536f0d83d4d
{
	meta:
		author = "ditekSHen"
		description = "Detects signed excutable of DiskCryptor open encryption solution that offers encryption of all disk partitions"
		thumbprint = "2022d012c23840314f5eeaa298216bec06035787"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Alexander Lomachevsky" and pe.signatures[i].serial=="03:5b:41:76:66:60:b0:8a:af:12:15:36:f0:d8:3d:4d")
}
