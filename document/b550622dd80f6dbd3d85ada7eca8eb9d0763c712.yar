rule malrtf_ole2link_alt_1 : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized RTF documents with OLE2Link exploit"
		os = "windows"
		filetype = "document"

	strings:
		$rtf_format_00 = "{\\rtf1"
		$rtf_format_01 = "{\\rt"
		$rtf_olelink_01 = "\\objdata" nocase
		$rtf_olelink_02 = "4f4c45324c696e6b" nocase
		$rtf_olelink_03 = "d0cf11e0a1b11ae1" nocase
		$rtf_payload_01 = "68007400740070003a002f002f00" nocase
		$rtf_payload_02 = "680074007400700073003a002f002f00" nocase
		$rtf_payload_03 = "6600740070003a002f002f00" nocase

	condition:
		any of ($rtf_format_*) and all of ($rtf_olelink_*) and any of ($rtf_payload_*)
}
