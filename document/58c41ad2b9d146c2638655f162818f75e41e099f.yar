import "pe"

rule PHISH_02Dez2015_attach_P_ORD_C_10156_124658
{
	meta:
		description = "Phishing Wave - file P-ORD-C-10156-124658.xls"
		author = "Florian Roth"
		reference = "http://myonlinesecurity.co.uk/purchase-order-124658-gina-harrowell-clinimed-limited-word-doc-or-excel-xls-spreadsheet-malware/"
		date = "2015-12-02"
		hash = "bc252ede5302240c2fef8bc0291ad5a227906b4e70929a737792e935a5fee209"
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "Execute" ascii
		$s2 = "Process WriteParameterFiles" fullword ascii
		$s3 = "WScript.Shell" fullword ascii
		$s4 = "STOCKMASTER" fullword ascii
		$s5 = "InsertEmailFax" ascii

	condition:
		uint16(0)==0xcfd0 and filesize <200KB and all of them
}
