import "pe"

rule disable_firewall
{
	meta:
		author = "x0r"
		description = "Disable Firewall"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
		$c1 = "RegSetValue"
		$r1 = "FirewallPolicy"
		$r2 = "EnableFirewall"
		$r3 = "FirewallDisableNotify"
		$s1 = "netsh firewall add allowedprogram"

	condition:
		(1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}
