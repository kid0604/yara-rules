import "hash"

rule RansomHouseRule3
{
	meta:
		description = "Detect the Malware of RansomHouse Rule 3, if you need help, call NSFOCUS's support team 400-8186868, please."
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "unknown error - system account operation failed" fullword ascii
		$s2 = "command not found - does the file exist? do you run it like ./commandname if the file is in the same folder?" fullword ascii
		$s3 = "warning - no output from process" fullword ascii
		$s4 = "failed to create file to run process" fullword ascii
		$s5 = "esxcli system account command not found" fullword ascii
		$s6 = "failed to start process" fullword ascii
		$s7 = "unknown error - operation failed" fullword ascii
		$s8 = "failed to chmod file to run process" fullword ascii
		$s9 = "Dear IT Department and Company Management! If you are reading this message, it means that your network infrastructure has been c" ascii
		$s10 = "esxcli --formatter=csv vm process list" fullword ascii
		$s11 = "process was killed by force" fullword ascii
		$s12 = "rm -rf /var/log/*.log" fullword ascii
		$s13 = "RunProcess" fullword ascii
		$s14 = "ps | grep sshd | grep -v -e grep -e root -e 12345 | awk '{print \"kill -9\", $2}' | sh " fullword ascii
		$s15 = "esxcli command not found" fullword ascii
		$s16 = "esxcli --formatter=csv system account list" fullword ascii
		$s17 = "esxcli --formatter=csv network ip interface ipv4 get" fullword ascii
		$s18 = "Dear IT Department and Company Management! If you are reading this message, it means that your network infrastructure has been c" ascii
		$s19 = "welcomeset" fullword ascii
		$s20 = "ompromised. Look for 'How To Restore Your Files.txt' document for more information." fullword ascii

	condition:
		uint16(0)==0x457f and filesize <200KB and 8 of them
}
