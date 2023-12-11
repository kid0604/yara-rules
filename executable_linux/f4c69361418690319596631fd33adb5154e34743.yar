import "pe"

rule Linux_Portscan_Shark_2
{
	meta:
		description = "Detects Linux Port Scanner Shark"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
		date = "2016-04-01"
		super_rule = 1
		hash1 = "5f80bd2db608a47e26290f3385eeb5bfc939d63ba643f06c4156704614def986"
		hash2 = "90af44cbb1c8a637feda1889d301d82fff7a93b0c1a09534909458a64d8d8558"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "usage: %s <fisier ipuri> <fisier useri:parole> <connect timeout> <fail2ban wait> <threads> <outfile> <port>" fullword ascii
		$s2 = "Difference between server modulus and host modulus is only %d. It's illegal and may not work" fullword ascii
		$s3 = "rm -rf scan.log" fullword ascii

	condition:
		all of them
}
