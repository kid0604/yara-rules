rule Str_Win32_Internet_API
{
	meta:
		author = "@adricnet"
		description = "Match Windows Inet API call"
		method = "String match, trim the As"
		reference = "https://github.com/dfirnotes/rules"
		os = "windows"
		filetype = "executable"

	strings:
		$wininet_call_closeh = "InternetCloseHandle"
		$wininet_call_readf = "InternetReadFile"
		$wininet_call_connect = "InternetConnect"
		$wininet_call_open = "InternetOpen"

	condition:
		( any of ($wininet_call*))
}
