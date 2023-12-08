rule MAL_LNX_CamaroDragon_Sheel_Oct23
{
	meta:
		description = "Detects CamaroDragon's tool named sheel"
		author = "Florian Roth"
		reference = "https://research.checkpoint.com/2023/the-dragon-who-sold-his-camaro-analyzing-custom-router-implant/"
		date = "2023-10-06"
		score = 85
		hash1 = "7985f992dcc6fcce76ee2892700c8538af075bd991625156bf2482dbfebd5a5a"
		os = "linux"
		filetype = "executable"

	strings:
		$x1 = "-h server_ip -p server_port -i update_index[0-4] [-r]" ascii fullword
		$s1 = "read_ip" ascii fullword
		$s2 = "open fail.%m" ascii fullword
		$s3 = "ri:h:p:" ascii fullword
		$s4 = "update server list success!" ascii fullword

	condition:
		uint16(0)==0x457f and filesize <30KB and (1 of ($x*) or 3 of them ) or 4 of them
}
