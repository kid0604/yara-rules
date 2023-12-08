rule MAL_RANSOM_SH_ESXi_Attacks_Feb23_2
{
	meta:
		description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers"
		author = "Florian Roth"
		reference = "https://dev.to/xakrume/esxiargs-encryption-malware-launches-massive-attacks-against-vmware-esxi-servers-pfe"
		date = "2023-02-06"
		score = 85
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "echo \"START ENCRYPT: $file_e SIZE: $size_kb STEP SIZE: " ascii

	condition:
		filesize <10KB and 1 of them
}
