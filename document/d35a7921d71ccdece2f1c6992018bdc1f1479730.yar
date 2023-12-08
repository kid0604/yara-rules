rule ppaction
{
	meta:
		ref = "https://blog.nviso.be/2017/06/07/malicious-powerpoint-documents-abusing-mouse-over-actions/amp/"
		Description = "Malicious PowerPoint Documents Abusing Mouse Over Actions"
		hash = "68fa24c0e00ff5bc1e90c96e1643d620d0c4cda80d9e3ebeb5455d734dc29e7"
		description = "Malicious PowerPoint Documents Abusing Mouse Over Actions"
		os = "windows"
		filetype = "document"

	strings:
		$a = "ppaction" nocase

	condition:
		$a
}
