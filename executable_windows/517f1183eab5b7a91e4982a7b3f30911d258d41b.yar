import "pe"

rule MAL_Trickbot_Oct19_6
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-10-02"
		hash1 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"
		hash2 = "cf99990bee6c378cbf56239b3cc88276eec348d82740f84e9d5c343751f82560"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "D:\\MyProjects\\spreader\\Release\\ssExecutor_x86.pdb" fullword ascii
		$s1 = "%s\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%s" fullword ascii
		$s2 = "%s\\appdata\\roaming\\%s" fullword ascii
		$s3 = "WINDOWS\\SYSTEM32\\TASKS" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <=400KB and (1 of ($x*) or 3 of them )
}
