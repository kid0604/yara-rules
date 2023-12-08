import "pe"

rule INDICATOR_KB_CERT_02fa994d660de659ee9037ecb437d766
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0cb6bde041b58dbd4ec64bd5a3be38c50f17bb3d"
		hash = "0868a2a7b5e276d3a4a40cdef994de934d33d62a689d7207a31fd57d012ef948"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Piriform Software Ltd" and pe.signatures[i].serial=="02:fa:99:4d:66:0d:e6:59:ee:90:37:ec:b4:37:d7:66")
}
