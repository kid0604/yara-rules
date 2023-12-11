rule Medusa_locker
{
	meta:
		Description = "This is a simple powerful rule to detect Medusa Locker"
		auther = "@FarghlyMal"
		Data = "13/4/2023"
		cape_type = "MedusaLocker Payload"
		description = "Rule to detect Medusa Locker ransomware"
		os = "windows"
		filetype = "executable"

	strings:
		$S1 = "bcdedit.exe /set {default} recoveryenabled No" wide
		$S2 = "bcdedit.exe /set {default} bootstatuspolicy ignorea" wide
		$S3 = "bcdedit.exe /set {default} recoveryenab" wide
		$S4 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" wide
		$S5 = "wmic.exe SHADOWCOPY /nointeractive" wide
		$S6 = "[LOCKER] Run scanning..." wide
		$S7 = "[LOCKER] Stop and delete services" wide
		$S8 = "{8761ABBD-7F85-42EE-B272-A76179687C63}" wide
		$S9 = "[LOCKER] Sleep at 60 seconds..." wide

	condition:
		uint16(0)==0x5A4D and 5 of ($S*)
}
