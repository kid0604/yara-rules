rule Str_Win32_Winsock2_Library
{
	meta:
		author = "@adricnet"
		description = "Match Winsock 2 API library declaration"
		method = "String match"
		reference = "https://github.com/dfirnotes/rules"
		os = "windows"
		filetype = "executable"

	strings:
		$ws2_lib = "Ws2_32.dll" nocase
		$wsock2_lib = "WSock32.dll" nocase

	condition:
		( any of ($ws2_lib,$wsock2_lib))
}
