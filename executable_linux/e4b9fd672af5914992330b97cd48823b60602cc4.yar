import "pe"

rule MALWARE_Linux_HelloKitty
{
	meta:
		author = "ditekSHen"
		description = "Detects Linux version of HelloKitty ransomware"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "exec_pipe:%s" ascii
		$s2 = "Error InitAPI !!!" fullword ascii
		$s3 = "No Files Found !!!" fullword ascii
		$s4 = "Error open log File:%s" fullword ascii
		$s5 = "%ld - Files Found  " fullword ascii
		$s6 = "Total VM run on host:" fullword ascii
		$s7 = "error:%d open:%s" fullword ascii
		$s8 = "work.log" fullword ascii
		$s9 = "esxcli vm process kill" ascii
		$s10 = "readdir64" fullword ascii
		$s11 = "%s_%d.block" fullword ascii
		$s12 = "EVP_EncryptFinal_ex" fullword ascii
		$s13 = ".README_TO_RESTORE" fullword ascii
		$m1 = "COMPROMISED AND YOUR SENSITIVE PRIVATE INFORMATION WAS STOLEN" ascii nocase
		$m2 = "damage them without special software" ascii nocase
		$m3 = "leaking or being sold" ascii nocase
		$m4 = "Data will be Published and/or Sold" ascii nocase

	condition:
		uint16(0)==0x457f and (6 of ($s*) or (2 of ($m*) and 2 of ($s*)) or 8 of them )
}
