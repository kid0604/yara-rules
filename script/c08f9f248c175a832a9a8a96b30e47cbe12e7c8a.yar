rule APT_MAL_CN_Wocao_getos_py
{
	meta:
		description = "Python getos utility"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$smb_1 = {
            00 00 00 85 ff 53 4d 42 72 00 00 00 00 18 53 c8
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe
            00 00 ff b4 00 62 00 02 50 43 20 4e 45 54 57 4f
            52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 00 02
            4c 41 4e 4d 41 4e 31 2e 30 00 02 57 69 6e 64 6f
            77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70
            73 20 33 2e 31 61 00 02 4c 4d 31 2e 32 58 30 30
            32 00 02 4c 41 4e 4d 41 4e 32 2e 31 00 02 4e 54
            20 4c 4d 20 30 2e 31 32 00
        }
		$smb_2 = {
            00 00 00 c8 ff 53 4d 42 73 00 00 00 00 18 03 c8
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe
            00 00 3f b5 0c ff 00 c8 00 04 11 32 00 00 00 00
            00 00 00 28 00 00 00 00 00 d4 00 00 a0 8d 00 4e
            54 4c 4d 53 53 50 00 01 00 00 00 07 82 88 a2 00
            00 00 00 28 00 00 00 00 00 00 00 28 00 00 00 05
            01 28 0a 00 00 00 0f 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00
        }
		$smbstr_1 = "\\x00\\x00\\x00\\x85\\xffSMBr\\x00\\x00\\x00\\x00\\x18S\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xfe\\x00\\x00\\xff\\xb4\\x00b\\x00\\x02PC NETWORK PROGRAM 1.0\\x00\\x02LANMAN1.0\\x00\\x02Windows for Workgroups 3.1a\\x00\\x02LM1.2X002\\x00\\x02LANMAN2.1\\x00\\x02NT LM 0.12\\x00"
		$smbstr_2 = "\\x00\\x00\\x00\\xc8\\xffSMBs\\x00\\x00\\x00\\x00\\x18\\x03\\xc8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xfe\\x00\\x00?\\xb5\\x0c\\xff\\x00\\xc8\\x00\\x04\\x112\\x00\\x00\\x00\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x00\\x00\\xd4\\x00\\x00\\xa0\\x8d\\x00NTLMSSP\\x00\\x01\\x00\\x00\\x00\\x07\\x82\\x88\\xa2\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x00\\x00\\x00\\x00(\\x00\\x00\\x00\\x05\\x01(\\n\\x00\\x00\\x00\\x0f\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
		$code_1 = "return 'Other error.'" ascii wide
		$code_2 = "sblob = buf[47:47 + sbl]" ascii wide
		$code_3 = "re.split('[\\x00-,]+', y[-4])" ascii wide
		$code_4 = "('').join(sblob[off:off + hlen].split('\\x00'))" ascii wide
		$code_5 = "banner = '%s    %s' % (hostname, native)" ascii wide
		$code_6 = "banner = '%s\\\\%s    %s' % (dm, hostname, native)" ascii wide
		$tsk_1 = "PushTask" ascii wide
		$tsk_2 = "parse_task" ascii wide
		$tsk_3 = "commit_task" ascii wide
		$str_1 = "Usage: getos.py <ip-range|ip-file>" ascii wide
		$str_2 = "The path '%s' write fails." ascii wide
		$str_3 = "Receive a signal %d," ascii wide
		$str_4 = "Scan Complete!" ascii wide
		$str_5 = "line: %d, %s: %s" ascii wide
		$str_6 = "Other error." ascii wide

	condition:
		( all of ($smb_*)) or ( all of ($smbstr_*)) or (3 of ($code_*)) or ( all of ($tsk_*)) or (3 of ($str_*))
}
