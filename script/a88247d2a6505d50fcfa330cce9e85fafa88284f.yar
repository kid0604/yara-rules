rule SUSP_EXPL_POC_VMWare_Workspace_ONE_CVE_2022_22954_Apr22_1
{
	meta:
		old_rule_name = "EXPL_POC_VMWare_Workspace_ONE_CVE_2022_22954_Apr22"
		description = "Detects payload as seen in PoC code to exploit Workspace ONE Access freemarker server-side template injection CVE-2022-22954"
		author = "Florian Roth"
		reference = "https://github.com/sherlocksecurity/VMware-CVE-2022-22954"
		reference2 = "https://twitter.com/rwincey/status/1512241638994853891/photo/1"
		date = "2022-04-08"
		modified = "2025-03-29"
		score = 60
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x2 = "${\"freemarker.template.utility.Execute\"?new()("
		$x3 = "cat /etc/passwd\")).(#execute=#instancemanager.newInstance(\"freemarker.template.utility.Execute"
		$x4 = "cat /etc/passwd\\\")).(#execute=#instancemanager.newInstance(\\\"freemarker.template.utility.Execute"
		$x5 = "cat /etc/shadow\")).(#execute=#instancemanager.newInstance(\"freemarker.template.utility.Execute"
		$x6 = "cat /etc/shadow\\\")).(#execute=#instancemanager.newInstance(\\\"freemarker.template.utility.Execute"
		$fpg1 = "All Rights"
		$fpg2 = "<html"
		$fpg3 = "<HTML"
		$fpg4 = "Copyright" ascii wide
		$fpg5 = "License"
		$fpg6 = "<?xml"
		$fpg7 = "Help" fullword
		$fpg8 = "COPYRIGHT" ascii wide fullword
		$fpg9 = "Backup"
		$fp1 = "severity: critical"

	condition:
		1 of ($x*) and not 1 of ($fp*)
}
