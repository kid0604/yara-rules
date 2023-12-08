rule Linux_Trojan_BPFDoor_0f768f60
{
	meta:
		author = "Elastic Security"
		id = "0f768f60-1d6c-4af9-8ae3-c1c8fbbd32f4"
		fingerprint = "55097020a70d792e480542da40b91fd9ab0cc23f8736427f398998962e22348e"
		creation_date = "2022-05-10"
		last_modified = "2022-05-10"
		threat_name = "Linux.Trojan.BPFDoor"
		reference_sample = "3a1b174f0c19c28f71e1babde01982c56d38d3672ea14d47c35ae3062e49b155"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan BPFDoor"
		filetype = "executable"

	strings:
		$a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
		$a2 = "/sbin/mingetty /dev/tty7" ascii fullword
		$a3 = "pickup -l -t fifo -u" ascii fullword
		$a4 = "kdmtmpflush" ascii fullword
		$a5 = "avahi-daemon: chroot helper" ascii fullword
		$a6 = "/sbin/auditd -n" ascii fullword

	condition:
		all of them
}
