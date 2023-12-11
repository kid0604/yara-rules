import "pe"

rule INDICATOR_KB_CERT_00b383658885e271129a43d19de40c1fc6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ef234051b4b83086b675ff58aca85678544c14da39dbdf4d4fa9d5f16e654e2f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Elekon" and pe.signatures[i].serial=="00:b3:83:65:88:85:e2:71:12:9a:43:d1:9d:e4:0c:1f:c6")
}
