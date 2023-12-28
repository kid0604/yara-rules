rule APT10_ChChes_lnk
{
	meta:
		description = "LNK malware ChChes downloader"
		author = "JPCERT/CC Incident Response Group"
		hash = "6d910cd88c712beac63accbc62d510820f44f630b8281ee8b39382c24c01c5fe"
		os = "windows"
		filetype = "executable"

	strings:
		$v1a = "cmd.exe"
		$v1b = "john-pc"
		$v1c = "win-hg68mmgacjc"
		$v1d = "t-user-nb"
		$v1e = "C:\\Users\\suzuki\\Documents\\my\\card.rtf" wide

	condition:
		$v1a and ($v1b or $v1c or $v1d) or $v1e
}
