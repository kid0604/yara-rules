rule SUSP_LNX_Linux_Malware_Indicators_Aug20_1
{
	meta:
		description = "Detects indicators often found in linux malware samples"
		author = "Florian Roth (Nextron Systems)"
		score = 65
		reference = "Internal Research"
		date = "2020-08-03"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "&& chmod +x" ascii
		$s2 = "|base64 -" ascii
		$s3 = " /tmp" ascii
		$s4 = "|curl " ascii
		$s5 = "whoami" ascii fullword
		$fp1 = "WITHOUT ANY WARRANTY" ascii
		$fp2 = "postinst" ascii fullword
		$fp3 = "THIS SOFTWARE IS PROVIDED" ascii fullword
		$fp4 = "Free Software Foundation" ascii fullword

	condition:
		filesize <400KB and 3 of ($s*) and not 1 of ($fp*)
}