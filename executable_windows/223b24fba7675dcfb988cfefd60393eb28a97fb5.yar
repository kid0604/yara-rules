rule LOG_EXPL_MOVEit_Exploitation_Indicator_Jun23_1
{
	meta:
		description = "Detects a potential compromise indicator found in MOVEit Transfer logs"
		author = "Florian Roth"
		reference = "https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response"
		date = "2023-06-01"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "POST /moveitisapi/moveitisapi.dll action=m2 " ascii
		$x2 = " GET /human2.aspx - 443 " ascii

	condition:
		1 of them
}
