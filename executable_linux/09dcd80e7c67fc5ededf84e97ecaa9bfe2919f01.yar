rule Linux_Trojan_BPFDoor_59e029c3
{
	meta:
		author = "Elastic Security"
		id = "59e029c3-a57c-44ad-a554-432efc6b591a"
		fingerprint = "cc9b75b1f1230e3e2ed289ef5b8fa2deec51197e270ec5d64ff73722c43bb4e8"
		creation_date = "2022-05-10"
		last_modified = "2022-05-10"
		threat_name = "Linux.Trojan.BPFDoor"
		reference_sample = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.BPFDoor malware"
		filetype = "executable"

	strings:
		$a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
		$a2 = "/sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d" ascii fullword
		$a3 = "avahi-daemon: chroot helper" ascii fullword
		$a4 = "/sbin/mingetty /dev/tty6" ascii fullword
		$a5 = "ttcompat" ascii fullword

	condition:
		all of them
}
