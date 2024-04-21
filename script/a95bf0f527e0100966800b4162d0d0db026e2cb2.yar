rule case_19438_files_MalFiles_install
{
	meta:
		description = "19438 - file install.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "041b0504742449c7c23750490b73bc71e5c726ad7878d05a73439bd29c7d1d19"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Key Exchange\" /rl highest /tr \"%programdata%\\sshd\\ssh.exe -i %programdata%" ascii
		$x2 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Key Exchange\" /rl highest /tr \"%programdata%\\sshd\\ssh.exe -i %programdata%" ascii
		$x3 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Server\" /rl highest  /tr \"%programdata%\\sshd\\sshd.exe -f %programdata%\\sshd" ascii
		$x4 = "schtasks.exe /create /sc minute /mo 1 /tn \"SSH Server\" /rl highest  /tr \"%programdata%\\sshd\\sshd.exe -f %programdata%\\sshd" ascii
		$s5 = "onfig\\keys\\id_rsa -N -R 369:127.0.0.1:2222 root@185.206.146.129 -o StrictHostKeyChecking=no -o ServerAliveInterval=60 -o Serve" ascii
		$s6 = "ssh-keygen -f %programdata%\\sshd\\config\\id_rsa -t rsa  -N \"\"" fullword ascii
		$s7 = "icacls %programdata%\\sshd\\config\\keys\\id_rsa /grant:r \"%username%\":\"(R)\"" fullword ascii
		$s8 = "icacls %programdata%\\sshd\\config\\id_rsa /grant:r \"%username%\":\"(R)\"" fullword ascii
		$s9 = "icacls %programdata%\\sshd\\config\\keys\\id_rsa /inheritance:r" fullword ascii
		$s10 = "icacls %programdata%\\sshd\\config\\id_rsa /inheritance:r" fullword ascii
		$s11 = "g\\sshd_config\"" fullword ascii
		$s12 = "liveCountMax=15\"" fullword ascii

	condition:
		uint16(0)==0x6540 and filesize <2KB and 1 of ($x*) and all of them
}
