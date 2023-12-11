import "pe"

rule INDICATOR_KB_CERT_06de439ba2df4dcd8240c211d60cdf5e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2650a1205bd7720381c00bdee5aede0ee333dc13"
		hash1 = "e3bc81a59fc45dfdfcc57b0078437061cb8c3396e1d593fcf187e3cdf0373ed1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Microleaves LTD" and pe.signatures[i].serial=="06:de:43:9b:a2:df:4d:cd:82:40:c2:11:d6:0c:df:5e")
}
