rule MAL_IcedID_GZIP_LDR_202104
{
	meta:
		author = "Thomas Barabosch, Telekom Security"
		date = "2021-04-12"
		modified = "2023-01-27"
		description = "2021 initial Bokbot / Icedid loader for fake GZIP payloads"
		reference = "https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240"
		os = "windows"
		filetype = "executable"

	strings:
		$internal_name = "loader_dll_64.dll" fullword
		$string0 = "_gat=" wide
		$string1 = "_ga=" wide
		$string2 = "_gid=" wide
		$string4 = "_io=" wide
		$string5 = "GetAdaptersInfo" fullword
		$string6 = "WINHTTP.dll" fullword
		$string7 = "DllRegisterServer" fullword
		$string8 = "PluginInit" fullword
		$string9 = "POST" wide fullword
		$string10 = "aws.amazon.com" wide fullword

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ($internal_name or all of ($s*)) or all of them
}
