rule APT_MAL_SideWinder_implant
{
	meta:
		author = "AT&T Alien Labs"
		description = "Detects SideWinder final payload"
		hash1 = "c568238dcf1e30d55a398579a4704ddb8196b685"
		reference = "https://cybersecurity.att.com/blogs/labs-research/a-global-perspective-of-the-sidewinder-apt"
		os = "windows"
		filetype = "executable"

	strings:
		$code = { 1B 30 05 00 C7 00 00 00 00 00 00 00 02 28 03 00
               00 06 7D 12 00 00 04 02 02 FE 06 23 00 00 06 73
               5B 00 00 0A 14 20 88 13 00 00 15 73 5C 00 00 0A
               7D 13 00 00 04 02 02 FE 06 24 00 00 06 73 5B 00
               00 0A 14 20 88 13 00 00 15 73 5C 00 00 0A 7D 15
               00 00 04 02 7B 12 00 00 04 6F 0E 00 00 06 2C 1D
               02 28 1F 00 00 06 02 7B 12 00 00 04 16 6F 0F 00
               00 06 02 7B 12 00 00 04 6F 06 00 00 06 02 7B 12
               00 00 04 6F 10 00 00 06 2C 23 02 28 20 00 00 06
               02 28 21 00 00 06 02 7B 12 00 00 04 16 }
		$strings = { 
         2E 00 73 00 69 00 66 00 00 09 2E 00 66 00 6C 00
         63 00 00 1B 73 00 65 00 6C 00 65 00 63 00 74 00
         65 00 64 00 46 00 69 00 6C 00 65 00 73
      }

	condition:
		uint16(0)==0x5A4D and all of them
}
