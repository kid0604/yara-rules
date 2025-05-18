rule SUSP_LNX_StackString_Technique_Jan25
{
	meta:
		description = "Detects suspicious Linux binaries using stack-based string manipulation techniques, which are often used to generate PTY (pseudo-terminal) device names for stealth or persistence, seen being used by SEASPY and Bluez backdoors"
		author = "MalGamy (Nextron System)"
		date = "2025-01-23"
		reference = "https://www.securityweek.com/newly-discovered-turla-malware-targets-linux-systems/"
		hash = "0e65a80c6331a0e8d7df05ac217a8a7fe03b88f1d304f2ff0a26b92ed89153f3"
		hash = "3e0312ce8d0c1e5c192dbb93cac4770a1205c56dc9d02a0510c7e10a15251de5"
		hash = "301d58a6a1819466e77209dbf8ca635cbee3b45516e5ee228fea50ae4a27b7d5"
		hash = "957c0c135b50d1c209840ec7ead60912a5ccefd2873bf5722cb85354cea4eb37"
		hash = "5e3c128749f7ae4616a4620e0b53c0e5381724a790bba8314acb502ce7334df2"
		hash = "654b7c5b667e4d70ebb5fb1807dcd1ee5b453f45424eb59a287d86ad8d0598a1"
		hash = "ac6a8ec0b92935b7faab05ca21a42ed9eecdc9243fcf1449cc8f050de38e4c4f"
		score = 75
		os = "linux"
		filetype = "executable"

	strings:
		$op1 = {C7 45 E0 70 71 72 73 C7 45 E4 74 75 76 77 C7 45 E8 78 79 7A 61 C7 45 EC 62 63 64 65 C6 45 F0 00 C7 45 C0 30 31 32 33 C7 45 C4 34 35 36 37 C7 45 C8 38 39 61 62 C7 45 CC 63 64 65 66}

	condition:
		uint32be(0)==0x7f454c46 and filesize <4MB and $op1
}
