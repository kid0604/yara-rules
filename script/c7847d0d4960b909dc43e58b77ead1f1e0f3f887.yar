rule SUSP_Base64_Encoded_Exploit_Indicators_Dec21
{
	meta:
		description = "Detects base64 encoded strings found in payloads of exploits against log4j CVE-2021-44228"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/Reelix/status/1469327487243071493"
		date = "2021-12-10"
		modified = "2021-12-13"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sa1 = "Y3VybCAtcy"
		$sa2 = "N1cmwgLXMg"
		$sa3 = "jdXJsIC1zI"
		$sb1 = "fHdnZXQgLXEgLU8tI"
		$sb2 = "x3Z2V0IC1xIC1PLS"
		$sb3 = "8d2dldCAtcSAtTy0g"
		$fp1 = "<html"

	condition:
		1 of ($sa*) and 1 of ($sb*) and not 1 of ($fp*)
}
