rule INDICATOR_RTF_Forms_HTML_Execution
{
	meta:
		description = "detects RTF files with Forms.HTML:Image.1 or Forms.HTML:Submitbutton.1 OLE objects referencing file or HTTP URLs."
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$img_clsid = "12d11255c65ccf118d6700aa00bdce1d" ascii nocase
		$sub_clsid = "10d11255c65ccf118d6700aa00bdce1d" ascii nocase
		$http_url = "6800740074007000" ascii nocase
		$file_url = "660069006c0065003a" ascii nocase

	condition:
		uint32(0)==0x74725c7b and filesize <1500KB and ($img_clsid or $sub_clsid) and ($http_url or $file_url)
}
