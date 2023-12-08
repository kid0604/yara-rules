rule Sofacy_Bundestag_Batch_alt_1
{
	meta:
		description = "Sofacy Bundestags APT Batch Script"
		author = "Florian Roth"
		reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
		date = "2015-06-19"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "for %%G in (.pdf, .xls, .xlsx, .doc, .docx) do (" ascii
		$s2 = "cmd /c copy"
		$s3 = "forfiles"

	condition:
		filesize <10KB and all of them
}
