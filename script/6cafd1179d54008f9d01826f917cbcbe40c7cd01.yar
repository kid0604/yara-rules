rule APT_MAL_CN_Wocao_xserver_powershell_b64encoded
{
	meta:
		description = "Piece of Base64 encoded data from the XServer PowerShell dropper"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows"
		filetype = "script"

	strings:
		$header_47000 = "5T39c9u2kr/nr2A0Ny2VKIzkfLRJntuJHafPN/nwWG777rUZDy3BNq8UqSEpx26b"
		$header_25667 = "5T1rc9u2st/zKxjNmZZKFEZyErdJ6nZsx+nxnTjxWGp77mkzHlqCbd5SpIak/Gjr"

	condition:
		any of them
}
