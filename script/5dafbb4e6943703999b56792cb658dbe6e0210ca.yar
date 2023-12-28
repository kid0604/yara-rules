rule malware_sqroot_webphp
{
	meta:
		description = "sqroot drop web page using unknown actors"
		author = "JPCERT/CC Incident Response Group"
		hash = "8b9f229012512b9e4fb924434caa054275410574c5b0c364b850bb2ef70a0f3d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$func1 = "send_download_file_as_exe($filename)" ascii
		$func2 = "check_remote_client()" ascii
		$func3 = "mylog('[e]');" ascii
		$func4 = "mylog('[z]');" ascii
		$func5 = "mylog('[4]');" ascii
		$func6 = "mylog('[*]');" ascii
		$func7 = "mylog('[p]');" ascii
		$func8 = "mylog($flag)" ascii
		$func9 = "get_remote_ip()" ascii

	condition:
		uint32(0)==0x68703f3c and 4 of ($func*)
}
