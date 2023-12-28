rule BlackTech_AresPYDoor_str
{
	meta:
		description = "AresPYDoor in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash = "52550953e6bc748dc4d774fbea66382cc2979580173a7388c01589e8cb882659"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$ares1 = "ares.desktop"
		$ares2 = "~/.ares"
		$ares3 = "grep -v .ares .bashrc >"
		$log1 = "[-]Error! server_hello: status_code=%d"
		$log2 = "[i]runcmd: %s"
		$log3 = "[i]send_output: posting data=%s"
		$log4 = "[i]server_hello: %s"
		$log5 = "[i]starting server_hello"

	condition:
		5 of them
}
