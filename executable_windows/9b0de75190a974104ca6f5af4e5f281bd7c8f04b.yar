rule BlackTech_TSCookie_rat
{
	meta:
		description = "TSCookie malware module"
		author = "JPCERT/CC Incident Response Group"
		hash = "2bd13d63797864a70b775bd1994016f5052dc8fd1fd83ce1c13234b5d304330d"
		os = "windows"
		filetype = "executable"

	strings:
		$w1d = "Date: %s" wide
		$w1a = "[-] Failed to initialize **** API" wide
		$w1b = "IPv6Test" wide

	condition:
		all of them
}
