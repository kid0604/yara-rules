import "pe"

rule malicious_LNK_files
{
	meta:
		author = "@patrickrolsen"
		description = "Detects malicious LNK files commonly used in phishing and malware attacks"
		os = "windows"
		filetype = "executable"

	strings:
		$magic = {4C 00 00 00 01 14 02 00}
		$s1 = "\\RECYCLER\\" wide
		$s2 = "%temp%" wide
		$s3 = "%systemroot%\\system32\\cmd.exe" wide
		$s5 = "svchost.exe" wide
		$s6 = "lsass.exe" wide
		$s7 = "csrss.exe" wide
		$s8 = "winlogon.exe" wide
		$s10 = "%appdata%" wide
		$s11 = "%programdata%" wide
		$s12 = "%localappdata%" wide
		$s13 = ".cpl" wide

	condition:
		($magic at 0) and any of ($s*)
}
