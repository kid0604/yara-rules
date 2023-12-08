rule LOG_EXPL_MOVEit_Exploitation_Indicator_Jun23_2
{
	meta:
		description = "Detects a potential compromise indicator found in MOVEit Transfer logs"
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response"
		date = "2023-06-03"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/105.0.5195.102+Safari/537.36" ascii
		$a2 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/105.0.5195.54+Safari/537.36" ascii
		$s1 = " POST /moveitisapi/moveitisapi.dll" ascii
		$s2 = " POST /guestaccess.aspx"
		$s3 = " POST /api/v1/folders/"
		$s4 = "/files uploadType=resumable&"
		$s5 = " action=m2 "

	condition:
		1 of ($a*) and 3 of ($s*) or all of ($s*)
}
