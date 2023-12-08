rule APT_MAL_CN_Wocao_agent_py
{
	meta:
		description = "Strings from Python version of Agent"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a = "vpshex.decode"
		$b = "self._newsock.recv"
		$c = "Rsock.connect"
		$d = /MAX_DATALEN\s?=\s?10240/
		$e = /LISTEN_MAXCOUNT\s?=\s?80/
		$f = "ListenSock.listen(LISTEN_MAXCOUNT)"
		$g = "nextsock.send(head)"
		$h = "elif transnode"
		$i = "infobuf[4:6]"
		$key = "L\\x1bh\\x0bj\\x18\\tAZ6\\x1fV&*\\x03D}_\\x03{\\x07n\\x03w0pRBSg\\n*"

	condition:
		1 of them
}
