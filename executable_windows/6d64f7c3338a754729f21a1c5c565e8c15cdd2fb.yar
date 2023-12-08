rule dat_NaslLib
{
	meta:
		description = "Chinese Hacktool Set - file NaslLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
		$s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
		$s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1360KB and all of them
}
