rule Linux_Shellcode_Generic_932ed0f0
{
	meta:
		author = "Elastic Security"
		id = "932ed0f0-bd43-4367-bcc3-ecd8f65b52ee"
		fingerprint = "7aa4619d2629b5d795e675d17a6e962c6d66a75e11fa884c0b195cb566090070"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Shellcode.Generic"
		reference_sample = "f357597f718f86258e7a640250f2e9cf1c3363ab5af8ddbbabb10ebfa3c91251"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux shellcode"
		filetype = "executable"

	strings:
		$a = { E3 50 89 E2 53 89 E1 B0 0B CD 80 31 C0 40 CD 80 }

	condition:
		all of them
}
