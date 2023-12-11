import "hash"

rule BLACKMOON_BANKER
{
	meta:
		description = "Detect the risk of Malware blackmoon  Rule 2"
		detail = "blackmoon update"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "BlackMoon RunTime Error:" nocase wide ascii
		$s2 = "\\system32\\rundll32.exe" wide ascii
		$s3 = "cmd.exe /c ipconfig /flushdns" wide ascii
		$s4 = "\\system32\\drivers\\etc\\hosts.ics" wide ascii

	condition:
		all of them
}
