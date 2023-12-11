rule APT_PS1_SysAid_EXPL_ForensicArtifacts_Nov23_1 : SCRIPT
{
	meta:
		description = "Detects forensic artifacts found in attacks on SysAid on-prem software exploiting CVE-2023-47246"
		author = "Florian Roth"
		score = 85
		reference = "https://www.sysaid.com/blog/service-desk/on-premise-software-security-vulnerability-notification"
		date = "2023-11-09"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "if ($s -match '^(Sophos).*\\.exe\\s') {echo $s; $bp++;}" ascii wide
		$x2 = "$s=$env:SehCore;$env:SehCore=\"\";Invoke-Expression $s;" ascii wide

	condition:
		1 of them
}
