rule SUSP_LNX_Base64_Exec_Apr24_alt_1 : SCRIPT
{
	meta:
		description = "Detects suspicious base64 encoded shell commands (as seen in Palo Alto CVE-2024-3400 exploitation)"
		author = "Christian Burkard"
		date = "2024-04-18"
		modified = "2025-01-17"
		reference = "Internal Research"
		score = 75
		id = "2da3d050-86b0-5903-97eb-c5f39ce4f3a3"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "curl http://" base64
		$s2 = "wget http://" base64
		$s3 = ";chmod 777 " base64
		$s4 = "/tmp/" base64
		$mirai = "country="

	condition:
		1 of ($s*) and not $mirai
}
