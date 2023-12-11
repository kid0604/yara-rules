import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EnableNetworkDiscovery
{
	meta:
		author = "ditekSHen"
		description = "Detects binaries manipulating Windows firewall to enable permissive network discovery"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "netsh advfirewall firewall set rule group=\"Network Discovery\" new enable=Yes" ascii wide nocase
		$s2 = "netsh advfirewall firewall set rule group=\"File and Printer Sharing\" new enable=Yes" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of them
}
