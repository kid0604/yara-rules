rule MAL_PHP_EFile_Apr23_1
{
	meta:
		description = "Detects malware "
		author = "Florian Roth"
		reference = "https://twitter.com/malwrhunterteam/status/1642988428080865281?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
		date = "2023-04-06"
		score = 75
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )" ascii
		$s2 = "C:\\\\ProgramData\\\\Browsers" ascii fullword
		$s3 = "curl_https($api_url." ascii

	condition:
		all of them
}
