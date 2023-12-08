rule APT_MAL_CN_Wocao_agent_py_b64encoded
{
	meta:
		description = "Piece of Base64 encoded data from Agent Python version"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$header = "QlpoOTFBWSZTWWDdHjgABDTfgHwQe////z/v/9+////6YA4cGPsAl2e8M9LSU128"

	condition:
		all of them
}
