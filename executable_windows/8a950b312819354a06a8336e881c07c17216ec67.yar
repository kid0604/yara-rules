rule Str_Win32_Wininet_Library
{
	meta:
		author = "@adricnet"
		description = "Match Windows Inet API library declaration"
		method = "String match"
		reference = "https://github.com/dfirnotes/rules"
		os = "windows"
		filetype = "executable"

	strings:
		$wininet_lib = "WININET.dll" nocase

	condition:
		( all of ($wininet*))
}
