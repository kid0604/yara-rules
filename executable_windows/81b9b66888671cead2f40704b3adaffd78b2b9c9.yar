import "pe"

rule INDICATOR_KB_CERT_df45b36c9d0bd248c3f9494e7ca822
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4b1efa2410d9aab12af6c0b624a3738dd06d3353"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MPO STORITVE d.o.o." and pe.signatures[i].serial=="df:45:b3:6c:9d:0b:d2:48:c3:f9:49:4e:7c:a8:22")
}
