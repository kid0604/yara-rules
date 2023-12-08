rule INDICATOR_RTF_LNK_Shell_Explorer_Execution
{
	meta:
		description = "detects RTF files with Shell.Explorer.1 OLE objects with embedded LNK files referencing an executable."
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$clsid = "c32ab2eac130cf11a7eb0000c05bae0b" ascii nocase
		$lnk_header = "4c00000001140200" ascii nocase
		$http_url = "6800740074007000" ascii nocase
		$file_url = "660069006c0065003a" ascii nocase

	condition:
		uint32(0)==0x74725c7b and filesize <1500KB and $clsid and $lnk_header and ($http_url or $file_url)
}
