import "pe"

rule conti_cobaltstrike_192145_icju1_0
{
	meta:
		description = "files - from files 192145.dll, icju1.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-05-09"
		hash1 = "29bc338e63a62c24c301c04961084013816733dad446a29c20d4413c5c818af9"
		hash2 = "e54f38d06a4f11e1b92bb7454e70c949d3e1a4db83894db1ab76e9d64146ee06"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cmd.exe /c echo NGAtoDgLpvgJwPLEPFdj>\"%s\"&exit" fullword ascii
		$s2 = "veniamatquiest90.dll" fullword ascii
		$s3 = "Quaerat magni assumenda nihil architecto labore ullam autem unde temporibus mollitia illum" fullword ascii
		$s4 = "Quaerat tempora culpa provident" fullword ascii
		$s5 = "Dolores ullam tempora error distinctio ut natus facere quibusdam" fullword ascii
		$s6 = "Velit consequuntur quisquam tempora error" fullword ascii
		$s7 = "Corporis minima omnis qui est temporibus sint quo error magnam" fullword ascii
		$s8 = "Quo omnis repellat ut expedita temporibus eius fuga error" fullword ascii
		$s9 = "Officia sit maiores deserunt nobis tempora deleniti aut et quidem fugit" fullword ascii
		$s10 = "Rerum tenetur sapiente est tempora qui deserunt" fullword ascii
		$s11 = "Sed nulla quaerat porro error excepturi" fullword ascii
		$s12 = "Aut tempore quo cumque dicta ut quia in" fullword ascii
		$s13 = "Doloribus commodi repudiandae voluptates consequuntur neque tempora ut neque nemo ad ut" fullword ascii
		$s14 = "Tempore possimus aperiam nam mollitia illum hic at ut doloremque" fullword ascii
		$s15 = "Et quia aut temporibus enim repellat dolores totam recusandae repudiandae" fullword ascii
		$s16 = "Dolorum eum ipsum tempora non et" fullword ascii
		$s17 = "Quas alias illum laborum tempora sit est rerum temporibus dicta et" fullword ascii
		$s18 = "Sed velit ipsa et dolor tempore sunt nostrum" fullword ascii
		$s19 = "Veniam voluptatem aliquam et eaque tempore tenetur possimus" fullword ascii
		$s20 = "Possimus suscipit placeat dolor quia tempora voluptas qui fugiat et accusantium" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) and 4 of them )) or ( all of them )
}
