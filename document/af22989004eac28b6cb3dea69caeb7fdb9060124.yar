rule rtf_objdata_urlmoniker_http
{
	meta:
		ref = "https://blog.nviso.be/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/"
		description = "Detects RTF documents containing object data with URLMoniker and HTTP"
		os = "windows"
		filetype = "document"

	strings:
		$header = "{\\rtf1"
		$objdata = "objdata 0105000002000000" nocase
		$urlmoniker = "E0C9EA79F9BACE118C8200AA004BA90B" nocase
		$http = "68007400740070003a002f002f00" nocase

	condition:
		$header at 0 and $objdata and $urlmoniker and $http
}
