rule SUSP_Doc_WordXMLRels_May22
{
	meta:
		description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
		date = "2022-05-30"
		modified = "2022-06-20"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
		score = 70
		os = "windows"
		filetype = "document"

	strings:
		$a1 = "<Relationships" ascii
		$a2 = "TargetMode=\"External\"" ascii
		$x1 = ".html!" ascii
		$x2 = ".htm!" ascii
		$x3 = "%2E%68%74%6D%6C%21" ascii
		$x4 = "%2E%68%74%6D%21" ascii

	condition:
		filesize <50KB and all of ($a*) and 1 of ($x*)
}
