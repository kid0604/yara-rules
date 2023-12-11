rule Office_OLE_DDE_alt_1
{
	meta:
		description = "Detects DDE in MS Office documents"
		author = "NVISO Labs"
		reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
		date = "2017-10-12"
		score = 50
		os = "windows"
		filetype = "document"

	strings:
		$a = /\x13\s*DDE\b[^\x14]+/ nocase
		$r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
		$r2 = "Adobe ARM Installer"

	condition:
		uint32be(0)==0xD0CF11E0 and $a and not 1 of ($r*)
}
