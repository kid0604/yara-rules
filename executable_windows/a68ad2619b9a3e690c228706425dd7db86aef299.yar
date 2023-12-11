rule Str_Win32_Http_API
{
	meta:
		author = "@adricnet"
		description = "Match Windows Http API call"
		method = "String match, trim the As"
		reference = "https://github.com/dfirnotes/rules"
		os = "windows"
		filetype = "executable"

	strings:
		$wininet_call_httpr = "HttpSendRequest"
		$wininet_call_httpq = "HttpQueryInfo"
		$wininet_call_httpo = "HttpOpenRequest"

	condition:
		( any of ($wininet_call_http*))
}
