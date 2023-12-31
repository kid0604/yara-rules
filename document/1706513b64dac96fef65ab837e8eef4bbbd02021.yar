rule EXP_potential_CVE_2017_11882
{
	meta:
		author = "ReversingLabs"
		reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-cobalt-strike-payload-exploiting-cve-2017-11882.html"
		description = "Detects Cobalt Strike payload exploiting CVE-2017-11882"
		os = "windows"
		filetype = "document"

	strings:
		$docfilemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$equation1 = "Equation Native" wide ascii
		$equation2 = "Microsoft Equation 3.0" wide ascii
		$mshta = "mshta"
		$http = "http://"
		$https = "https://"
		$cmd = "cmd" fullword
		$pwsh = "powershell"
		$exe = ".exe"
		$address = { 12 0C 43 00 }

	condition:
		uint16(0)==0xcfd0 and $docfilemagic at 0 and any of ($mshta,$http,$https,$cmd,$pwsh,$exe) and any of ($equation1,$equation2) and $address
}
