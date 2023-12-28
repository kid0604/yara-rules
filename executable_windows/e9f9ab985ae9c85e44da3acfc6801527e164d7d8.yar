rule Lazarus_Comebacker_strings
{
	meta:
		description = "Comebacker malware in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "1ff4421a99793acda5dd7412cb9a62301b14ed0a455edbb776f56471bef08f8f"
		os = "windows"
		filetype = "executable"

	strings:
		$postdata1 = "%s=%s&%s=%s&%s=%s&%s=%d&%s=%d&%s=%s" ascii
		$postdata2 = "Content-Type: application/x-www-form-urlencoded" wide
		$postdata3 = "Connection: Keep-Alive" wide
		$key = "5618198335124815612315615648487" ascii
		$str1 = "Hash error!" ascii wide
		$str2 = "Dll Data Error|" ascii wide
		$str3 = "GetProcAddress Error|" ascii wide
		$str4 = "Sleeping|" ascii wide
		$str5 = "%s|%d|%d|" ascii wide

	condition:
		all of ($postdata*) or $key or all of ($str*)
}
