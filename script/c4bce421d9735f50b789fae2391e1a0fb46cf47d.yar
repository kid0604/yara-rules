rule EQGRP_shellcode
{
	meta:
		description = "EQGRP Toolset Firewall - file shellcode.py"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "ac9decb971dd44127a6ca0d35ac153951f0735bb4df422733046098eca8f8b7f"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "execute_post = '\\xe8\\x00\\x00\\x00\\x00\\x5d\\xbe\\xef\\xbe\\xad\\xde\\x89\\xf7\\x89\\xec\\x29\\xf4\\xb8\\x03\\x00\\x00\\x00" ascii
		$s2 = "tiny_exec = '\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x03\\x00\\x01\\x00\\x00" ascii
		$s3 = "auth_id = '\\x31\\xc0\\xb0\\x03\\x31\\xdb\\x89\\xe1\\x31\\xd2\\xb6\\xf0\\xb2\\x0d\\xcd\\x80\\x3d\\xff\\xff\\xff\\xff\\x75\\x07" ascii
		$c1 = { e8 00 00 00 00 5d be ef be ad de 89 f7 89 ec 29 f4 b8 03 00 00 00 }
		$c3 = { 31 c0 b0 03 31 db 89 e1 31 d2 b6 f0 b2 0d cd 80 3d ff ff ff ff 75 07 }

	condition:
		1 of them
}
