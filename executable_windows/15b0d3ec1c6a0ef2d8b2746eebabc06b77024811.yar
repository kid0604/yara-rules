import "pe"

rule disable_taskmanager
{
	meta:
		author = "x0r"
		description = "Disable Task Manager"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
		$r1 = "DisableTaskMgr"

	condition:
		1 of ($p*) and 1 of ($r*)
}
