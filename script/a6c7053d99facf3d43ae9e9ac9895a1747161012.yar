rule WEBSHELL_JAVA_VersaMem_JAR_Aug24_1
{
	meta:
		description = "Detects VersaMem Java webshell samples (as used by Volt Typhoon)"
		author = "blacklotuslabs (modified by Florian Roth and X__Junior)"
		reference = "https://x.com/ryanaraine/status/1828440883315999117"
		date = "2024-08-27"
		modified = "2024-08-29"
		score = 75
		id = "9b666e61-cfa8-58b3-a362-772cd907c57c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sa1 = "com.versa.vnms.ui.TestMain"
		$sa2 = "captureLoginPasswordCode"
		$sa3 = "com/versa/vnms/ui/services/impl/VersaAuthenticationServiceImpl"
		$sa4 = "/tmp/.temp.data"
		$sa5 = "getInsertCode"
		$sa6 = "VersaMem"
		$sa7 = "Versa-Auth"
		$sb1 = "/tmp/.java_pid"
		$sb2 = {2f 75 73 72 2f 62 69 6e 2f 70 67 72 65 70 01 00 02 2d 66 01 00 25 6f 72 67 2e 61 70 61 63 68 65 2e 63 61 74 61 6c 69 6e 61 2e 73 74 61 72 74 75 70 2e 42 6f 6f 74 73 74 72 61 70 07}

	condition:
		filesize <5MB and (3 of them or all of ($sb*))
}
