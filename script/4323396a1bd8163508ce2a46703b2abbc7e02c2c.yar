rule Msfpayloads_msf
{
	meta:
		description = "Metasploit Payloads - file msf.sh"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		modified = "2022-08-18"
		hash1 = "320a01ec4e023fb5fbbaef963a2b57229e4f918847e5a49c7a3f631cb556e96c"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "export buf=\\" ascii

	condition:
		filesize <5MB and $s1
}
