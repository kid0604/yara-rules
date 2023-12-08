import "pe"

rule APT15_Malware_Mar18_BS2005
{
	meta:
		description = "Detects malware from APT 15 report by NCC Group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/HZ5XMN"
		date = "2018-03-10"
		hash1 = "750d9eecd533f89b8aa13aeab173a1cf813b021b6824bc30e60f5db6fa7b950b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "AAAAKQAASCMAABi+AABnhEBj8vep7VRoAEPRWLweGc0/eiDrXGajJXRxbXsTXAcZAABK4QAAPWwAACzWAAByrg==" fullword ascii
		$x2 = "AAAAKQAASCMAABi+AABnhKv3kXJJousn5YzkjGF46eE3G8ZGse4B9uoqJo8Q2oF0AABK4QAAPWwAACzWAAByrg==" fullword ascii
		$a1 = "http://%s/content.html?id=%s" fullword ascii
		$a2 = "http://%s/main.php?ssid=%s" fullword ascii
		$a3 = "http://%s/webmail.php?id=%s" fullword ascii
		$a9 = "http://%s/error.html?tab=%s" fullword ascii
		$s1 = "%s\\~tmp.txt" fullword ascii
		$s2 = "%s /C %s >>\"%s\" 2>&1" fullword ascii
		$s3 = "DisableFirstRunCustomize" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or 2 of them )
}
