rule malware_windows_winnti_loadperf_dll_loader
{
	meta:
		description = "Winnti APT group; gzwrite64 imported from loadoerf.ini"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/winnti-abuses-github/"
		author = "@mimeframe"
		md5 = "879ce99e253e598a3c156258a9e81457"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "loadoerf.ini" fullword ascii wide
		$s2 = "gzwrite64" fullword ascii wide

	condition:
		all of ($s*)
}
