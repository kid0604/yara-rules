rule LOG_EXPL_MOVEit_Exploitation_Indicator_Jun23_3
{
	meta:
		description = "Detects a potential compromise indicator found in MOVEit DMZ Web API logs"
		author = "Nasreddine Bencherchali"
		reference = "https://attackerkb.com/topics/mXmV0YpC3W/cve-2023-34362/rapid7-analysis"
		date = "2023-06-13"
		score = 70
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "TargetInvocationException" ascii
		$s2 = "MOVEit.DMZ.Application.Folders.ResumableUploadFilePartHandler.DeserializeFileUploadStream" ascii

	condition:
		all of ($s*)
}
