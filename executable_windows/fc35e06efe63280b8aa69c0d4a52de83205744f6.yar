import "pe"

rule INDICATOR_KB_CERT_0dfa4f0cff90319951b019a4681ebd2a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b85aacac6afb0bef5b6f1d744cd8c278030e6a3e"
		hash1 = "4eca4e0d3c06e4889917a473229b368bae02f0135f0ac68e937a72fca431ac8a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "deepinstruction O" and pe.signatures[i].serial=="0d:fa:4f:0c:ff:90:31:99:51:b0:19:a4:68:1e:bd:2a")
}
