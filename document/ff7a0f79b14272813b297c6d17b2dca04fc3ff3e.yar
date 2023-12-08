rule Office_OLE_DDEAUTO
{
	meta:
		description = "Detects DDE in MS Office documents"
		author = "NVISO Labs"
		reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
		date = "2017-10-12"
		score = 30
		os = "windows"
		filetype = "document"

	strings:
		$a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase

	condition:
		uint32be(0)==0xD0CF11E0 and $a
}
