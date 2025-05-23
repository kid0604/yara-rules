rule SUSP_EXPL_POC_VMWare_Workspace_ONE_CVE_2022_22954_Apr22_alt_2
{
	meta:
		old_rule_name = "EXPL_POC_VMWare_Workspace_ONE_CVE_2022_22954_Apr22"
		description = "Detects payload as seen in PoC code to exploit Workspace ONE Access freemarker server-side template injection CVE-2022-22954"
		author = "Florian Roth"
		reference = "https://github.com/sherlocksecurity/VMware-CVE-2022-22954"
		reference2 = "https://twitter.com/rwincey/status/1512241638994853891/photo/1"
		date = "2022-04-08"
		modified = "2025-03-29"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28" ascii
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

	condition:
		1 of ($x*) and not 1 of ($fp*)
}
