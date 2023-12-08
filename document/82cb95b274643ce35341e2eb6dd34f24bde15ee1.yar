rule mwi_document : exploitdoc maldoc
{
	meta:
		description = "MWI generated document"
		author = "@Ydklijnsma"
		source = "http://blog.0x3a.com/post/117760824504/analysis-of-a-microsoft-word-intruder-sample"
		os = "windows"
		filetype = "document"

	strings:
		$field_creation_tag = "{\\field{\\*\\fldinst { INCLUDEPICTURE"
		$mwistat_url = ".php?id="
		$field_closing_tag = "\\\\* MERGEFORMAT \\\\d}}{\\fldrslt}}"

	condition:
		all of them
}
