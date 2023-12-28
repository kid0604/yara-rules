rule Lazarus_simplecurl_strings
{
	meta:
		description = "Tool of simple curl in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "05ffcbda6d2e38da325ebb91928ee65d1305bcc5a6a78e99ccbcc05801bba962"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "Usage: [application name].exe url filename" ascii
		$str2 = "completely succeed!" ascii
		$str3 = "InternetOpenSession failed.." ascii
		$str4 = "HttpSendRequestA failed.." ascii
		$str5 = "HttpQueryInfoA failed.." ascii
		$str6 = "response code: %s" ascii
		$str7 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :" ascii

	condition:
		4 of ($str*)
}
