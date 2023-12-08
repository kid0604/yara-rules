import "pe"

rule INDICATOR_KB_CERT_15c5af15afecf1c900cbab0ca9165629
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "69735ec138c555d9a0d410c450d8bcc7c222e104"
		hash1 = "2ae575f006fc418c72a55ec5fdc26bc821aa3929114ee979b7065bf5072c488f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kompaniya Auttek" and pe.signatures[i].serial=="15:c5:af:15:af:ec:f1:c9:00:cb:ab:0c:a9:16:56:29")
}
