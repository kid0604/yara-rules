rule case_18543_documents_9771_lnk
{
	meta:
		description = "18543 - file documents-9771.lnk"
		author = "The DFIR Report via yarGen Rule Generator"
		reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
		date = "2023-08-28"
		hash1 = "57842fe8723ed6ebdf7fc17fc341909ad05a7a4feec8bdb5e062882da29fa1a8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Program Files\\Windows Photo Viewer\\PhotoViewer.dll" fullword wide
		$s2 = "6C:\\Program Files\\Windows Photo Viewer\\PhotoViewer.dll" fullword wide
		$s3 = "demurest.cmd" fullword wide
		$s4 = "|4HDj;" fullword ascii
		$s5 = "8G~{ta" fullword ascii
		$s6 = "'o&qxmD" fullword ascii
		$s7 = "rs<do?" fullword ascii

	condition:
		uint16(0)==0x004c and filesize <8KB and all of them
}
