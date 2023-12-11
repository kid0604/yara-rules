import "pe"

rule MAL_3CXDesktopApp_MacOS_UpdateAgent_Mar23
{
	meta:
		description = "Detects 3CXDesktopApp MacOS UpdateAgent backdoor component"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/patrickwardle/status/1641692164303515653?s=20"
		date = "2023-03-30"
		hash = "9e9a5f8d86356796162cee881c843cde9eaedfb3"
		score = 80
		os = "macos"
		filetype = "executable"

	strings:
		$a1 = "/3CX Desktop App/.main_storage" ascii
		$x1 = ";3cx_auth_token_content=%s;__tutma=true"
		$s1 = "\"url\": \"https://"
		$s3 = "/dev/null"
		$s4 = "\"AccountName\": \""

	condition:
		uint16(0)==0xfeca and filesize <6MB and (1 of ($x*) or ($a1 and all of ($s*))) or all of them
}
