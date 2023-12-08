import "pe"

rule APT1_WEBC2_RAVE
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting APT1 threat group's use of iniet.exe and cmd.exe"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "iniet.exe" wide ascii
		$2 = "cmd.exe" wide ascii
		$3 = "SYSTEM\\CurrentControlSet\\Services\\DEVFS" wide ascii
		$4 = "Device File System" wide ascii

	condition:
		3 of them
}
