rule Linux_Hacktool_Outlaw_cf069e73
{
	meta:
		author = "Elastic Security"
		id = "cf069e73-21f8-494c-b60e-286c033d2d55"
		fingerprint = "25169be28aa92f36a6d7cb803056efe1b7892a78120b648dc81887bc66eae89d"
		creation_date = "2025-02-21"
		last_modified = "2025-03-07"
		description = "Outlaw SSH bruteforce component fom the Dota3 package"
		threat_name = "Linux.Hacktool.Outlaw"
		reference_sample = "c3efbd6b5e512e36123f7b24da9d83f11fffaf3023d5677d37731ebaa959dd27"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$ssh_key_1 = "MIIJrTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI8vKBZRGKsHoCAggA"
		$ssh_key_2 = "MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBBC3juWsJ7DsDd2wH2XI+vUBIIJ"
		$ssh_key_3 = "UCQ2viiVV8pk3QSUOiwionAoe4j4cBP3Ly4TQmpbLge9zRfYEUVe4LmlytlidI7H"
		$ssh_key_4 = "O+bWbjqkvRXT9g/SELQofRrjw/W2ZqXuWUjhuI9Ruq0qYKxCgG2DR3AcqlmOv54g"
		$path_1 = "/home/eax/up"
		$path_2 = "/var/tmp/dota"
		$path_3 = "/dev/shm/ip"
		$path_4 = "/dev/shm/p"
		$path_5 = "/var/tmp/.systemcache"
		$cmd_1 = "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'"
		$cmd_2 = "cd ~; chattr -ia .ssh; lockr -ia .ssh"
		$cmd_3 = "sort -R b | awk '{ if ( NF == 2 ) print } '> p || cat b | awk '{ if ( NF == 2 ) print } '> p; sort -R a"
		$cmd_4 = "rm -rf /var/tmp/dota*"
		$cmd_5 = "rm -rf a b c d p ip ab.tar.gz"

	condition:
		( all of ($ssh_key*)) or (3 of ($path*) and 3 of ($cmd*))
}
