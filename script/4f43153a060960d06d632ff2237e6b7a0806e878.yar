import "pe"

rule Sofacy_Bundestag_Batch
{
	meta:
		description = "Sofacy Bundestags APT Batch Script"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
		date = "2015-06-19"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "for %%G in (.pdf, .xls, .xlsx, .doc, .docx)" ascii
		$s2 = "cmd /c copy"
		$s3 = "forfiles"

	condition:
		filesize <10KB and 2 of them
}
