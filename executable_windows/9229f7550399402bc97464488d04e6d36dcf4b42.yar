import "pe"

rule INDICATOR_KB_CERT_00d7c432e8d4edef515bfb9d1c214ff0f5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6256d3ca79330f7bd912a88e59f9a4f3bdebdcd6b9c55cda4e733e26583b3d61"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LLC \"MILKY PUT\"" and pe.signatures[i].serial=="00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5")
}
