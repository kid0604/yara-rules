import "pe"

rule MALWARE_Linux_UNK02
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown/unidentified Linux malware"
		os = "linux"
		filetype = "executable"

	strings:
		$rf1 = "[]A\\A]A^A_" ascii
		$rf2 = "[A\\A]A^A_]" ascii
		$f1 = "/bin/basH" ascii fullword
		$f2 = "/proc/seH" ascii fullword
		$f3 = "/dev/ptsH" ascii fullword
		$f4 = "pqrstuvwxyzabcde" ascii fullword
		$f5 = "libnss_%s.so.%d.%d" ascii fullword

	condition:
		uint16(0)==0x457f and ( all of ($f*) and #rf1>3 and #rf2>3)
}
