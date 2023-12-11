import "pe"

rule MALWARE_Win_BazarLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects BazarLoader variants"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Startdelay for %d ms to avoid some dynamic AV detects!" ascii
		$s2 = "Use Debug for moving faster!" ascii
		$s3 = "Logging Mutex %s to %s" ascii
		$s4 = "FIRST AND ONLY COPY RUNNING! Mutex %s" ascii
		$s5 = "the most secret 3d GetWinApiPointers line in the world!" ascii
		$s6 = "[+] makeMD5hash. " ascii

	condition:
		uint16(0)==0x5a4d and 3 of ($s*)
}
