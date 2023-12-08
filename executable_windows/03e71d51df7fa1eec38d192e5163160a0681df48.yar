rule Delphi_FormShow
{
	meta:
		author = "_pusher_"
		description = "Look for Form.Show function"
		date = "2016-06"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 53 8B D8 B2 01 8B C3 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3 }
		$c1 = { 53 48 83 EC 20 48 89 CB 48 89 D9 B2 01 E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }

	condition:
		any of them
}
